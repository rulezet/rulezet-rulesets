rule Win_Spyware_WOW_15
{
strings:
	$a0 = { 558bec83c4f0b8583d4000e8e0f7ffff68e43d40006a006801001f00e82bf9ffff85c0751a68f43d40006a006801001f00e816f9ffff85c07505e8f5fdffff }


condition:
	$a0
}