rule Win_Trojan_Bruterdep_1
{
strings:
	$a0 = { 5357565152e800000000598b098bd180f2ab80fa67741e6681f1dcba6681f9df7774120f318bd80f70caff0f312bc35a595e5f5bc3 }


condition:
	$a0
}