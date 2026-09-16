rule Win_Trojan_Close_1
{
strings:
	$a0 = { 8bd5e8b3feb44033d2b99002e8a9fec3 }


condition:
	$a0
}