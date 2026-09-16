rule Win_Trojan_Offi_1
{
strings:
	$a0 = { a6440180f4908db644018bfeb92c01ac32c4aae2fa }


condition:
	$a0
}