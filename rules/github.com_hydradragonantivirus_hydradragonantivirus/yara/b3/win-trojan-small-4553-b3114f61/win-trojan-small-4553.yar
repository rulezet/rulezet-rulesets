rule Win_Trojan_Small_4553
{
strings:
	$a0 = { 81c0e9??400052515050ff108daabebc }


condition:
	$a0
}