rule Win_Trojan_Warpcom2_1
{
strings:
	$a0 = { a34000833e4000027d0731c09ad8004700bf8c011e57b83f0050bf44001e579a72002900c4 }


condition:
	$a0
}