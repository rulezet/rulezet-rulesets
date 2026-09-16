rule Win_Trojan_Eumel_11
{
strings:
	$a0 = { 5b81eb0a018bebb801faba4559cd16b41aba64facd218db62802bf0001b90300fcf3a4b419cd212ea27002b40e }


condition:
	$a0
}