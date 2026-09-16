rule Win_Trojan_Peed_277
{
strings:
	$a0 = { e8af00000068461301005981c138dc000081c146130100baff89bffff7d289d6 }


condition:
	$a0
}