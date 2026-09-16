rule Win_Trojan_Eumel_5
{
strings:
	$a0 = { 5d81ed0a01b801faba4559cd16b41aba64facd218db61402bf0001b90300fcf3a4b419cd212ea25c02b40eb202 }


condition:
	$a0
}