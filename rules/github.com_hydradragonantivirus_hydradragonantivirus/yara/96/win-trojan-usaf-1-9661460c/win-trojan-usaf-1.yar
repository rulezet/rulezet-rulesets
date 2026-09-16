rule Win_Trojan_Usaf_1
{
strings:
	$a0 = { a603c686a503e889bea803b800425a59cd21b440b909008d96a503cd218bce83e903898ea003 }


condition:
	$a0
}