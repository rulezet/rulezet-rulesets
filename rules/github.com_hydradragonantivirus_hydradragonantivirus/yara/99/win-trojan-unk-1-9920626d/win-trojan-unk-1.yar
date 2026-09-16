rule Win_Trojan_UNK_1
{
strings:
	$a0 = { fdc606d603ff90b44033d2b9f703cd21 }


condition:
	$a0
}