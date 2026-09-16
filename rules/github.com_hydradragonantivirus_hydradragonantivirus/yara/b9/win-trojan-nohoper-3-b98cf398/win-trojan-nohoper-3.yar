rule Win_Trojan_Nohoper_3
{
strings:
	$a0 = { 6800204000c32bc050e800000000ff253030400000 }


condition:
	$a0
}