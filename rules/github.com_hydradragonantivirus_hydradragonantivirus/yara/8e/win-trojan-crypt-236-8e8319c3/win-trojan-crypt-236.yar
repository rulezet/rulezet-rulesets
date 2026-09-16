rule Win_Trojan_Crypt_236
{
strings:
	$a0 = { b9eb055580ebfacc5233c133cc59eb0fb9eb0509 }


condition:
	$a0
}