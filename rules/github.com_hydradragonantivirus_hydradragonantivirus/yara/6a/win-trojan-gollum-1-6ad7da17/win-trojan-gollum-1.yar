rule Win_Trojan_Gollum_1
{
strings:
	$a0 = { bf0001b91c00f3a45e568db403008bfeb91900ac }


condition:
	$a0
}