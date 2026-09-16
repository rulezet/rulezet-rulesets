rule Win_Trojan_VGEN_73
{
strings:
	$a0 = { ffba7a032e89163502b430cd218b2e02ffff008b1e2c008edaa392008c069000891ef01f8cfc2ea800e83d01c43e8a }


condition:
	$a0
}