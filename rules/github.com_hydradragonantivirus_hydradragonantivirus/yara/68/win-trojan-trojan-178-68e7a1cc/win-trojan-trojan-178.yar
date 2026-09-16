rule Win_Trojan_Trojan_178
{
strings:
	$a0 = { 010e5650568cc880c4108ec08bfeb97f00f3a4bad400b41acd21ba7901b102b44ecd21723fbaf200b8023dcd218bd8061f8bd7b980fdb43fcd21057f0081 }


condition:
	$a0
}