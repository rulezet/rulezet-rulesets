rule Win_Trojan_Gergana_15
{
strings:
	$a0 = { e05e81c60001bf0001b9b600f3a4b8 }


condition:
	$a0
}