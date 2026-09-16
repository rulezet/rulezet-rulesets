rule Win_Trojan_VB_1766
{
strings:
	$a0 = { 7272616765656e00120000ff03290000000209007a697263 }


condition:
	$a0
}