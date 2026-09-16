rule Win_Trojan_Zbot_1309
{
strings:
	$a0 = { 558bec81ec68010000535657c785dcfeffff00000000c785ecfeffff00000000c785d0feffff64000000c785e8feffff15000000c745f8 }


condition:
	$a0
}