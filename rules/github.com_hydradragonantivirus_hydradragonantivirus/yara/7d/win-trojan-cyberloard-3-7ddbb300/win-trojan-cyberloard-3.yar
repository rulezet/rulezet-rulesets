rule Win_Trojan_Cyberloard_3
{
strings:
	$a0 = { cd21b44050b9c800ba0001cd21721e582e8b0e9a005acd21b801575a59cd21b8014359ba9e00 }


condition:
	$a0
}