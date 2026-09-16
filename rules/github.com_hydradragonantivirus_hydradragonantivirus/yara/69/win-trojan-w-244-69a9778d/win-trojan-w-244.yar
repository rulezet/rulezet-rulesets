rule Win_Trojan_W_244
{
strings:
	$a0 = { 608b583c03c36681385045753e8b707803b5 }


condition:
	$a0
}