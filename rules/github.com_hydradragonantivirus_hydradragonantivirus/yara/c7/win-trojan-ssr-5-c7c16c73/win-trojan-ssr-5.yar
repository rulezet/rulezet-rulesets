rule Win_Trojan_SSR_5
{
strings:
	$a0 = { b44eba460703d6b94c00cd217210eb3db44fcd217208eb35b43ecd21ebf2b42acd21 }


condition:
	$a0
}