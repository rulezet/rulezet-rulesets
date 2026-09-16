rule Win_Trojan_Virus9_2
{
strings:
	$a0 = { b44fcd217202ebb0b43bba7501cd217202eb9ccd20 }


condition:
	$a0
}