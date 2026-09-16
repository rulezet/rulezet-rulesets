rule Win_Trojan_Cbot_1
{
strings:
	$a0 = { 405f40003e5f3c00300000003c656e643e0000003c626567696e3e005e5f5e }


condition:
	$a0
}