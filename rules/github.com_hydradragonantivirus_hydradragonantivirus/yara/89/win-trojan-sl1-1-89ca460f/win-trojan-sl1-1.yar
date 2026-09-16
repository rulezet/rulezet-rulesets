rule Win_Trojan_SL1_1
{
strings:
	$a0 = { 8a0cb40081e1f0048a20750db92900f2ae8a188a043c5274e26800f307bf00008b048b7e005e }


condition:
	$a0
}