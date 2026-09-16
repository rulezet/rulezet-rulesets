rule Win_Trojan_Ldpinch_26
{
strings:
	$a0 = { 83ec008bf681e2480f00006816b147004e03fdf7d681fd67383e0033f0[0-59]c97465746e21f781 }


condition:
	$a0
}