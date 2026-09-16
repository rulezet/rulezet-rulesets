rule Win_Trojan_CopyProtected_1
{
strings:
	$a0 = { c80500108ec0be000133ffb9ea01fafcf3a48c061a01ea1c000000fb0e1fc60613008cc60611018090b419cd212ea2 }


condition:
	$a0
}