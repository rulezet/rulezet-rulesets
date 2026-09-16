rule Win_Trojan_NTIT_1
{
strings:
	$a0 = { b000b900008bd62e8b1e0e01cd216160b4402e8b1e0e01b9f401cd216181c3f4012df401 }


condition:
	$a0
}