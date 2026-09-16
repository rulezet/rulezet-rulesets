rule Win_Trojan_Peed_38
{
strings:
	$a0 = { b91432230f83c00101c3e2f985db74f5 }


condition:
	$a0
}