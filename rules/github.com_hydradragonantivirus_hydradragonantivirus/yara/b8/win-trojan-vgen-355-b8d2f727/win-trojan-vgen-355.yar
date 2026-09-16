rule Win_Trojan_VGEN_355
{
strings:
	$a0 = { 660fb6044667668d1c4081c3640e8a4702ff17ebeb5e6aeee89000e915fbdd6aeeb990d2e97602def4eee87e000fb4 }


condition:
	$a0
}