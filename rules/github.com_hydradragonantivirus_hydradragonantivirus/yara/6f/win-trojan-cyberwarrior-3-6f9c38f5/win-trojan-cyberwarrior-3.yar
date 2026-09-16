rule Win_Trojan_CyberWarrior_3
{
strings:
	$a0 = { b440ba7b0f8b1e7309e823027244b99c142bc8b440ba7b0fe814027235b440ba2509b91800e80702 }


condition:
	$a0
}