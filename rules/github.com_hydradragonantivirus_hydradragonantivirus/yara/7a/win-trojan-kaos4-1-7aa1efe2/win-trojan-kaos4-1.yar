rule Win_Trojan_KAOS4_1
{
strings:
	$a0 = { d1022e89a6d3028cc88ed0bcffef2e8a86b4022e8c86d50250061e0e0e071fffb6b0 }


condition:
	$a0
}