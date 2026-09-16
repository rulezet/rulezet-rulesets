rule Win_Trojan_VGEN_426
{
strings:
	$a0 = { e800005d81ed0901ba00feb41acd21bf00013e8db6e401b90600f3a48d96d801b44e33c9cd21b8023dba1efecd218986 }


condition:
	$a0
}