rule Win_Trojan_C_71
{
strings:
	$a0 = { 0200550000000100ffff0103000011010000020000000103 }


condition:
	$a0
}