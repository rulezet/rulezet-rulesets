rule Win_Trojan_Eumel_12
{
strings:
	$a0 = { 0b018bebb801faba4559cd16b41aba64facd218db62902bf0001b90300fcf3a4b419cd212ea27102b40eb202cd }


condition:
	$a0
}