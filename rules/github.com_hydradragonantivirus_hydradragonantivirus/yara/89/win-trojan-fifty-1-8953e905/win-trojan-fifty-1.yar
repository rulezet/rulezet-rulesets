rule Win_Trojan_Fifty_1
{
strings:
	$a0 = { 4f68894f77b600e80a00721033dbff47778a5768b90100b80103cdccc32e88260e01cdcc724c9c }


condition:
	$a0
}