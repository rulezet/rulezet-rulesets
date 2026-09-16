rule Win_Trojan_Crooked_1
{
strings:
	$a0 = { aa753aac32e4b109d3e091ad3d80fa7508ad3d8073740deb153df6c27512ad3d8075750a }


condition:
	$a0
}