rule Win_Trojan_TinyDI_6
{
strings:
	$a0 = { be000150568cc880c4108ec08bfeb96e00f3a4bad400b41acd21ba6801b44ecd21baf200b8023dcd218bd8061f8bd733c949b43fcd21056e005041b8004299cd }


condition:
	$a0
}