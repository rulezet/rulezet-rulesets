rule Win_Trojan_SillyC_234
{
strings:
	$a0 = { 81ee0701bf000103f756a5a55e8bd681c28e00b41acd21b44e33c98d948801cd2172188d94ac00b8023dcd218bd8e8 }


condition:
	$a0
}