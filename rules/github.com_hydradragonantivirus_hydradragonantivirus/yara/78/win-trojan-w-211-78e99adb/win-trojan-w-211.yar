rule Win_Trojan_W_211
{
strings:
	$a0 = { 880e8800ba8000b80103cd1372eae84900b80103fec133dbcd13ebdc }


condition:
	$a0
}