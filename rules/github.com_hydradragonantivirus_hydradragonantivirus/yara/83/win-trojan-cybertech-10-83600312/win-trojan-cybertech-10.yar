rule Win_Trojan_CyberTech_10
{
strings:
	$a0 = { e800005d81ed0700508db61d008bfeb9fa0090ac34 }


condition:
	$a0
}