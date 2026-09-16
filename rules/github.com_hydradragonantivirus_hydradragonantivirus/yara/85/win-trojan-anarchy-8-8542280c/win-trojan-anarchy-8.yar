rule Win_Trojan_Anarchy_8
{
strings:
	$a0 = { caaeaf9addc0adacbec5aeef8884caa0afe0cabaafcb812cc5aee288ca8cafcb072cc5aee288ca86afb6b7 }


condition:
	$a0
}