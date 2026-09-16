rule Win_Trojan_Eumel_3
{
strings:
	$a0 = { 81ed0b01b801faba4559cd16b41aba64facd218db61502bf0001b90300fcf3a4b419cd212ea21b02b40eb202cd2172 }


condition:
	$a0
}