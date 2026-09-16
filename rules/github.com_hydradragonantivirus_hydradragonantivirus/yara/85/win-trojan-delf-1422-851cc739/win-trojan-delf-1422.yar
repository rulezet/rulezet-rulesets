rule Win_Trojan_Delf_1422
{
strings:
	$a0 = { ba24fa4900b858fa4900e89929fcff6a0133c9ba68fa4900b87cfa4900e8a222fcff8d55ecb801000000e89d31f6ff8b45ecbaacfa4900e87450f6ff74088d45fce852d1ffff }


condition:
	$a0
}