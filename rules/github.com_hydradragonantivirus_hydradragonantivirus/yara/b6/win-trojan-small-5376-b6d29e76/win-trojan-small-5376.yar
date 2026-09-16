rule Win_Trojan_Small_5376
{
strings:
	$a0 = { 505b505e81c0008abfffe91300000089c3 }


condition:
	$a0
}