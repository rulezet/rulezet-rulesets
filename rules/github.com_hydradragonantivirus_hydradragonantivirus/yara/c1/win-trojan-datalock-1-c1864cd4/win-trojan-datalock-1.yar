rule Win_Trojan_Datalock_1
{
strings:
	$a0 = { 3e891ed5023e8c06d702ba1f02b82125 }


condition:
	$a0
}