rule Win_Trojan_Cfsk_1
{
strings:
	$a0 = { cf7504b8cf0ccf80fc4b7503eb06902eff2e38045053 }


condition:
	$a0
}