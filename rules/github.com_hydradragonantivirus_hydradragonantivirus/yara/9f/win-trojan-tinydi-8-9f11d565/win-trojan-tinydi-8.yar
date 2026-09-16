rule Win_Trojan_TinyDI_8
{
strings:
	$a0 = { 010e56568cc880c4108ec08bfeb95e00f3a4ba5801b44ecd217230ba9e00b8023dcd218bd8061f8bd749b43fcd21055e005033c9b8004299cd21595a52b4 }


condition:
	$a0
}