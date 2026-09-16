rule Win_Trojan_RockSteady_1
{
strings:
	$a0 = { 015058575058ab5058a495c3eb1c908cda9083c21090 }


condition:
	$a0
}