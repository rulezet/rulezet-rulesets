rule Win_Trojan_VGEN_566
{
strings:
	$a0 = { 33db33ff33edc300000000558bec508b460455e800005d2e3b46f15d76131e568ed88b7602ac3c }


condition:
	$a0
}