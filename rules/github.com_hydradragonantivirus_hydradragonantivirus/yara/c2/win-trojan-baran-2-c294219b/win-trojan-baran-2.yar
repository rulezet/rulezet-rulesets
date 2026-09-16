rule Win_Trojan_Baran_2
{
strings:
	$a0 = { 20d274887be69cf271af6213fd38b16960d74ca47b1e6f6e }


condition:
	$a0
}