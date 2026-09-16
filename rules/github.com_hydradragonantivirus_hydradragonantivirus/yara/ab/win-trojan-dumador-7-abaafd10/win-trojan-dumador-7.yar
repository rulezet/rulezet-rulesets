rule Win_Trojan_Dumador_7
{
strings:
	$a0 = { 7a65797e0a6f7269626b646d6f0a66656d63640a6865720a0a0a0a0a5a666f6b796f2a6f647e6f782a7e626f0a5a666f6b796f }


condition:
	$a0
}