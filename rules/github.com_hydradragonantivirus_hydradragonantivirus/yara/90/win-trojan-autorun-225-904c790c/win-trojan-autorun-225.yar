rule Win_Trojan_Autorun_225
{
strings:
	$a0 = { 6f70656e3d6f70656e207368656c6c5c6f70656e5c636f6d6d616e643d[0-60]5c73797333322e657865 }


condition:
	$a0
}