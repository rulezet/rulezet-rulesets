rule Win_Trojan_Dolphin_1
{
strings:
	$a0 = { 2000e800005d81ed0801061e0e1f8a8626032d050089864b05c7864d050500df864b05df864d05dec1df }


condition:
	$a0
}