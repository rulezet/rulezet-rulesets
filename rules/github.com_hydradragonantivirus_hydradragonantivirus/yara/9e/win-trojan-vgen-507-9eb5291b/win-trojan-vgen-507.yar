rule Win_Trojan_VGEN_507
{
strings:
	$a0 = { b8cd214e4e4e4e4e4e4074421e06b82135cd218c847401899c72010706b44abbffffcd21b4 }


condition:
	$a0
}