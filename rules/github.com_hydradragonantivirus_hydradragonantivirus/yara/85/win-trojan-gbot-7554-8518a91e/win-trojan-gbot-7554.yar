rule Win_Trojan_Gbot_7554
{
strings:
	$a0 = { e8a90000002bc9558bec81c4c0fdffff8d4c24446aff6a006a006a0083e1fe51 }


condition:
	$a0
}