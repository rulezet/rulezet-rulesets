rule Win_Trojan_W_212
{
strings:
	$a0 = { b107880e8300b80103cd1372ede84900b80103fec1cd13ebe1 }


condition:
	$a0
}