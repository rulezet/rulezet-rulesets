rule Win_Trojan_Polish_Minimal_1
{
strings:
	$a0 = { 3dcd218bd8b440ba0001b12dcd21b43ecd21b44febdcc3 }


condition:
	$a0
}