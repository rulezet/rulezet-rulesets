rule Win_Trojan_Kitana_20
{
strings:
	$a0 = { e800005b83eb03538d7713b1838034??46e2fa }


condition:
	$a0
}