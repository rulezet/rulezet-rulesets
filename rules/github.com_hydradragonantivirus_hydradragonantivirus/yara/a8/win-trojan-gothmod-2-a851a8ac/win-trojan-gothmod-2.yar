rule Win_Trojan_Gothmod_2
{
strings:
	$a0 = { 9a00003e005589e5b800019acd023e0081ec0001bf00000e57bfdc021e57b8ff00509a0c0b3e00bf21000e57bfdc031e }


condition:
	$a0
}