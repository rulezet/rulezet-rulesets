rule Win_Trojan_SSR_1
{
strings:
	$a0 = { ffcd21fec0742be800005e83ee112bff6a2007b1d6f3a46a001fa18400a30c00a18600a30e00 }


condition:
	$a0
}