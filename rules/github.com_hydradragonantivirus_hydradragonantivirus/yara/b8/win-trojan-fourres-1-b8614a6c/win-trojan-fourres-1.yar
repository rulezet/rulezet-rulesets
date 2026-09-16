rule Win_Trojan_Fourres_1
{
strings:
	$a0 = { c3b90400b440cd21c3b80043cd212e898e7d04b92000b80143cd21b8023dcd21c32e8b8e7904 }


condition:
	$a0
}