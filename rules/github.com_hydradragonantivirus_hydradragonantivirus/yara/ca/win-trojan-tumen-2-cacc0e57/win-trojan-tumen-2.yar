rule Win_Trojan_Tumen_2
{
strings:
	$a0 = { 8cc8488ed8812e03000001812e120000 }


condition:
	$a0
}