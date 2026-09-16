rule Win_Trojan_FireFly_2
{
strings:
	$a0 = { f604b9f20081370000817702000083c304e2f2 }


condition:
	$a0
}