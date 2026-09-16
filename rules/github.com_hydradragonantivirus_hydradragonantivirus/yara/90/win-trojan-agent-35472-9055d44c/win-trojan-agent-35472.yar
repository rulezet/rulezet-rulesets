rule Win_Trojan_Agent_35472
{
strings:
	$a0 = { 6a0068ff1901006805190100833c2400750b8d54 }


condition:
	$a0
}