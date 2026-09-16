rule Win_Trojan_VGEN_690
{
strings:
	$a0 = { ed0901ba00feb41acd21e80000bf00018db62a02b90600f3a48d961e02b44e33c9cd21e80000b8023dba1efecd21 }


condition:
	$a0
}