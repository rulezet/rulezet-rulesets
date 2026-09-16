rule Win_Trojan_IVP_25
{
strings:
	$a0 = { 8d9e????b971028ab6????2e8a2732e62e882743e2f5c3 }


condition:
	$a0
}