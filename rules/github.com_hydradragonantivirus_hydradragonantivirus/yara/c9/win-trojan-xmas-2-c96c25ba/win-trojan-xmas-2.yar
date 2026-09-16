rule Win_Trojan_XMas_2
{
strings:
	$a0 = { 8bf281c69b11bf0001b90300f3a48b }


condition:
	$a0
}