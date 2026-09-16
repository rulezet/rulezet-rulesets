rule Win_Trojan_Legacy_1
{
strings:
	$a0 = { c3b68715a49ee76867648b2e00002bdd553bf26a005fbe217ad594648927 }


condition:
	$a0
}