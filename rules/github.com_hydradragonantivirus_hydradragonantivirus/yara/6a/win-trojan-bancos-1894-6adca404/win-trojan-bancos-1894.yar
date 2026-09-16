rule Win_Trojan_Bancos_1894
{
strings:
	$a0 = { 457d06345f35fd7776e2099060d6ccead38efa92a78d60fd88cf47634d5e11c9a61b2c162e989bfd2269bbefc55cb2ba5da8f5110a9dc2f5da713116eae0bcb2328cd1c302fe }


condition:
	$a0
}