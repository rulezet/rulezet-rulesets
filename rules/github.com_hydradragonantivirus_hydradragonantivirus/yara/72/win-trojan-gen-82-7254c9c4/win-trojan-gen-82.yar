rule Win_Trojan_Gen_82
{
strings:
	$a0 = { 72dcfec42ea35001b80057e82f0083c91f5152b44033d2b9670151e81f00b8004233c933d2 }


condition:
	$a0
}