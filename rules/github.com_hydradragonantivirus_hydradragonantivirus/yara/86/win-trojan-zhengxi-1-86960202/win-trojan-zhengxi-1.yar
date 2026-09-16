rule Win_Trojan_Zhengxi_1
{
strings:
	$a0 = { bf4e7f2bc981d1ec225181ca0b0781f77730261a16c0e00eb310d3e95680db4380c9e4b91d99ea900003009b80fb }


condition:
	$a0
}