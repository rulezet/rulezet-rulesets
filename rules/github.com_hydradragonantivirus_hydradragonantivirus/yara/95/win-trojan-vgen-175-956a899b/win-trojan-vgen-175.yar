rule Win_Trojan_VGEN_175
{
strings:
	$a0 = { 03740156a5a45e8d5455b44ecd21ba9e00b8023de82f00722993b43fcd21803ce9741bb002e81b0097b15bb440 }


condition:
	$a0
}