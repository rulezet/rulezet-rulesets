rule Win_Trojan_VGEN_335
{
strings:
	$a0 = { 5d81ed0901ba00feb41acd21e80000bf00018db62702b90600f3a48d961b02b44e33c9cd21b8023dba1efecd21 }


condition:
	$a0
}