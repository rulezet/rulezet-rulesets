rule Win_Trojan_Mmust_1
{
strings:
	$a0 = { 558bec83c4e4535633c08945e48945e88945ecb838494000e800002c40be1467 }


condition:
	$a0
}