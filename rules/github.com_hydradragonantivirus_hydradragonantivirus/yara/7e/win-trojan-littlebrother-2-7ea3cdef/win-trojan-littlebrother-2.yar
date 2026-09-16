rule Win_Trojan_LittleBrother_2
{
strings:
	$a0 = { 061e5053523d004b7503e80b005a5b581f079d2eff2e }


condition:
	$a0
}