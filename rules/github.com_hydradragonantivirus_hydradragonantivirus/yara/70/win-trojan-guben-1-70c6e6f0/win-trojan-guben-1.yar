rule Win_Trojan_Guben_1
{
strings:
	$a0 = { e800005efc0e1f0e07bf0001b903005681c6e902f3a45ee85801b44732d25681c69b02cd215eb43b }


condition:
	$a0
}