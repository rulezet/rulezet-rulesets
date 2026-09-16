rule Win_Trojan_Dupl_1
{
strings:
	$a0 = { 03e9e800505351521e065657552e8b1e010181c30301538db7c205bf0001b90300fcf3a48becb8ffffcd2181fb34 }


condition:
	$a0
}