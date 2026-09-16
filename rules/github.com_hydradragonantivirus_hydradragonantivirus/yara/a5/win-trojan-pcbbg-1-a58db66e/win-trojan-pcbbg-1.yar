rule Win_Trojan_PCBBG_1
{
strings:
	$a0 = { e800005e81c6120089f7b96506b4 }


condition:
	$a0
}