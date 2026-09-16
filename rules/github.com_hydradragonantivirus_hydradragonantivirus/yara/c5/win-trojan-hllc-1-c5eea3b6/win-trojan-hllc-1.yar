rule Win_Trojan_HLLC_1
{
strings:
	$a0 = { b900540045023be70000060e1f8b0e0c008bf14e89f78cdb031e0a008ec3 }


condition:
	$a0
}