rule Win_Trojan_Tbrain_1
{
strings:
	$a0 = { 0a005589e531c09acd020a00e882ff5d31c09a16010a000000000000000000000000ba81008eda8c06460033ed }


condition:
	$a0
}