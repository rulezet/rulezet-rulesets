rule Win_Trojan_On4ever_1
{
strings:
	$a0 = { 6901434b8a073c397403fe07c3c60730ebf1ba6201b45b33c9cd21721250b96f00ba00018bd8b440cd215bb43ecd21 }


condition:
	$a0
}