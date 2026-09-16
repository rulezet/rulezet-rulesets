rule Win_Trojan_Swizzor_516
{
strings:
	$a0 = { e8000000005a81c2??020d00ffe2 }


condition:
	$a0
}