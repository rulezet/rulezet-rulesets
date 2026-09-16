rule Win_Trojan_VGEN_193
{
strings:
	$a0 = { bd04008d9eee05ffd340485e1fb23f5e1a7737d3c8794255f92b4e6ff1a9696ae98e69669ee69511b311b31d9124912c }


condition:
	$a0
}