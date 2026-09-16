rule Win_Trojan_Khizhnjak_14
{
strings:
	$a0 = { 8cc80506008ed8c7c3ec0181b7240164004b4b75f6 }


condition:
	$a0
}