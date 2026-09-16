rule Win_Trojan_Valhala_1
{
strings:
	$a0 = { 02d1e9412e310383c702e2f82e8b9ef40232dfd1e302 }


condition:
	$a0
}