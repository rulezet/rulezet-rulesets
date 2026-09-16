rule Win_Trojan_CyberTech_17
{
strings:
	$a0 = { e800005d81ed0700508db61d008bfeb92c0290ac34 }


condition:
	$a0
}