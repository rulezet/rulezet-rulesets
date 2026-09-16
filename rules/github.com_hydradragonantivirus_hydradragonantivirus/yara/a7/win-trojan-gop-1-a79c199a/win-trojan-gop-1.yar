rule Win_Trojan_Gop_1
{
strings:
	$a0 = { 736d74702e796561682e6e65 }

	$a1 = { 2d20474554204f494351 }


condition:
	$a0 and $a1
}