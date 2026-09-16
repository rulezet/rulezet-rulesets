rule Win_Trojan_Abigwar_1
{
strings:
	$a0 = { b8b40fcd103c02740d3c0374093c077402cd20b900a3b30001d98ed933db53bd500089de8b043c2074238bd0b020 }


condition:
	$a0
}