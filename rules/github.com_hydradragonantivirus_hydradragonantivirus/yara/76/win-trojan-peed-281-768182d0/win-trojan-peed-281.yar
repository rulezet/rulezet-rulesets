rule Win_Trojan_Peed_281
{
strings:
	$a0 = { e8af00000068461301005981c138dc000081c146130100baff }


condition:
	$a0
}