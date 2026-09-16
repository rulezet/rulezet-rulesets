rule Win_Trojan_Crypt_242
{
strings:
	$a0 = { 558bec83c4bc60c1e11cc1cf1c66bf1566c1e910c1ea }


condition:
	$a0
}