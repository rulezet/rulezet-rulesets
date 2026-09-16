rule Win_Trojan_Terminator_2
{
strings:
	$a0 = { 9d2bce2ea012002e300446ffe2f9 }


condition:
	$a0
}