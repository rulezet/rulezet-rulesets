rule Win_Trojan_YB_4
{
strings:
	$a0 = { e800005e83ee0356fc81c6f800bf0001a5a55e8d940101b41acd21e81700b41aba8000cd21be000133db33c0995633f6 }


condition:
	$a0
}