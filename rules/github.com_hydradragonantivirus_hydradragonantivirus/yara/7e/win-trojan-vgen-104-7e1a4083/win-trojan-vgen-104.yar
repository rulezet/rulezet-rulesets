rule Win_Trojan_VGEN_104
{
strings:
	$a0 = { 0901ba00feb41acd21bf00018db6ef01b90600f3a48d96e301b44e33c9cd21b8023dba1efecd213e8986e90193 }


condition:
	$a0
}