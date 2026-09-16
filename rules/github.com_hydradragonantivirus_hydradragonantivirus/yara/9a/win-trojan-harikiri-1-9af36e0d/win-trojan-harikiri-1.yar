rule Win_Trojan_Harikiri_1
{
strings:
	$a0 = { c20400052a2e657865015c052a2e636f6d36596f757220 }


condition:
	$a0
}