rule Win_Trojan_Peed_373
{
strings:
	$a0 = { 0f6fc381efade0ffff81ff531f000074??81ffda9a00007f }


condition:
	$a0
}