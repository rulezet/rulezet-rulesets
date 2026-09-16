rule Win_Trojan_Mirror_4
{
strings:
	$a0 = { 2153bb9a0326813f49485b7503eb }


condition:
	$a0
}