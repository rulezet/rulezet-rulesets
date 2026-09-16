rule Win_Trojan_Pcclient_11
{
strings:
	$a0 = { f3a4bf284040008d9500ffffff83c9ff33c0f2ae }


condition:
	$a0
}