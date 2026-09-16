rule Win_Trojan_Pojer_8
{
strings:
	$a0 = { e800005ef883ee0af8bb260003def82e8a943607f8b90f072e3017f843e2f9 }


condition:
	$a0
}