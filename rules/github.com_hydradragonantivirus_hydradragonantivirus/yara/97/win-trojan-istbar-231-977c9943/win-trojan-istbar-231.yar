rule Win_Trojan_Istbar_231
{
strings:
	$a0 = { 5c6e736973646c2e646c6c00687474703a2f2f7777772e7973627765622e636f6d2f }


condition:
	$a0
}