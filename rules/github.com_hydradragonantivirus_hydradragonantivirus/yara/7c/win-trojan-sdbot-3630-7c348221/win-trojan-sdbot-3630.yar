rule Win_Trojan_SdBot_3630
{
strings:
	$a0 = { d9b85aa0f21e2db85164552d418ecd93d3006d9ed970a8193a6e631448a8eab4b9bf77c080191b8cea2b6203cd8e0419fb0ede5bfb26495687db95d8faa125dec4d100abc69302fbb9aa81bf728a }


condition:
	$a0
}