rule Win_Trojan_Peed_419
{
strings:
	$a0 = { 558bec6aff681831400068f026400064a10000000050648925000000 }


condition:
	$a0
}