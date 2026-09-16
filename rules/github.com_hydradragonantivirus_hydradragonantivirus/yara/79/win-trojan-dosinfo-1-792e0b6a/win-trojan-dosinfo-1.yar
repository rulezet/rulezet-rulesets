rule Win_Trojan_Dosinfo_1
{
strings:
	$a0 = { a37a29bf7a291e57bf7c291e57bf370d0e579a4607c204c6067f2c12c6067e2c01c606802c36 }


condition:
	$a0
}