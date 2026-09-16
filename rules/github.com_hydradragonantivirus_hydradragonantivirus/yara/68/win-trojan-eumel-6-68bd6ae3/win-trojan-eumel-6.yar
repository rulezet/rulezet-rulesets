rule Win_Trojan_Eumel_6
{
strings:
	$a0 = { e800005d939381ed0a01b801faba4559cd16b41aba64facd218db61602bf0001b90300fcf3a4b419cd212ea25e02b40e }


condition:
	$a0
}