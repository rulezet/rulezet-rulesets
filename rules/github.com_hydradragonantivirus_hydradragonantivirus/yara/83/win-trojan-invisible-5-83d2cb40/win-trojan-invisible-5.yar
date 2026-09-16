rule Win_Trojan_Invisible_5
{
strings:
	$a0 = { ba39f17100760081c131e916177a0030970f2e740087ed432c0000f2e2f1 }


condition:
	$a0
}