rule Win_Trojan_Gergana_3
{
strings:
	$a0 = { c6fd5e81c60001bf0001b9de00f3a4 }


condition:
	$a0
}