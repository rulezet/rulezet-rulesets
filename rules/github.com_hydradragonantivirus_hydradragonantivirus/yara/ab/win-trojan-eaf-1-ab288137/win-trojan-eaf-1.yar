rule Win_Trojan_EAF_1
{
strings:
	$a0 = { e800005e83ee0383bc310000742c89f381c33a0089f781c77d028b8c31008b072bc189074343038c }


condition:
	$a0
}