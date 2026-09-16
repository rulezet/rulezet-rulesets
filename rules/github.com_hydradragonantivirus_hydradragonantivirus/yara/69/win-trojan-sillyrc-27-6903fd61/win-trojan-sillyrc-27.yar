rule Win_Trojan_SillyRC_27
{
strings:
	$a0 = { 0150e800005b83eb078bf381c65300bf0001b90400fcf3a4b4accd2180fcaa7501c30e1f8bf3b820008ec0bf0000 }


condition:
	$a0
}