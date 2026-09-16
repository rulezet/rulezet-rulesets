rule Win_Trojan_Grog_19
{
strings:
	$a0 = { cd21bb0057937220cd218ac180c91f4932c1741052 }


condition:
	$a0
}