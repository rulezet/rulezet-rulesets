rule Win_Trojan_Bancos_1732
{
strings:
	$a0 = { b9b20f7c370ceae546dd7773048ae64c1c2fc6641973bc9b86bd2b77a6f4dc6e981a86898e4070001811b4c15d413a10e0155a47b49fccfff4fae87d1dcf70357f5db12e77a0 }


condition:
	$a0
}