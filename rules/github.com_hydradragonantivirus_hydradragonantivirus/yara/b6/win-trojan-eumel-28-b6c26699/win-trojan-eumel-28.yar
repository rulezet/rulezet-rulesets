rule Win_Trojan_Eumel_28
{
strings:
	$a0 = { 81ed0b01b801faba4559cd16b41aba64facd218db63702bf0001b90300fcf3a4b419cd212ea2d002b40eb202cd }


condition:
	$a0
}