rule Win_Trojan_Talon_1
{
strings:
	$a0 = { 0600550004000100ffffee060000f001000005000000ee06 }


condition:
	$a0
}