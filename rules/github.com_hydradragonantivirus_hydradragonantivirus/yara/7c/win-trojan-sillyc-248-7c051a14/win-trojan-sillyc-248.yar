rule Win_Trojan_SillyC_248
{
strings:
	$a0 = { 31c9ba0301b44ecd21720231c009c00f857800 }


condition:
	$a0
}