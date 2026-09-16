rule Win_Trojan_Mirror_6
{
strings:
	$a0 = { 9a0326813f49485b7503eb45901e0e }


condition:
	$a0
}