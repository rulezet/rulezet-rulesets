rule Win_Trojan_Rape_1
{
strings:
	$a0 = { baed01b90300b43fcd697303eb5b9033 }


condition:
	$a0
}