rule Win_Trojan_Amilia_2
{
strings:
	$a0 = { 40b94e06ba0001e85a00eb5190b8 }


condition:
	$a0
}