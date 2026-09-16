rule Win_Trojan_Gen_92
{
strings:
	$a0 = { a48bfdc3b104d3e00ac6fec1d3e00ac2 }


condition:
	$a0
}