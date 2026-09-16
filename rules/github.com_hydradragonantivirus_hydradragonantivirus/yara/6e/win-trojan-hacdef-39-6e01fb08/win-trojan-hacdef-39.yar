rule Win_Trojan_Hacdef_39
{
strings:
	$a0 = { 53340a5c426173d164805c5c2e5c0000e0496d335c68786465662d726b313030 }


condition:
	$a0
}