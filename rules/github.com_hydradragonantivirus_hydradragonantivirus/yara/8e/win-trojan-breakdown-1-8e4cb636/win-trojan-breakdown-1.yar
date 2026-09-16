rule Win_Trojan_Breakdown_1
{
strings:
	$a0 = { a764a3e814b1f6de446918a5a182806b21adabfd162e2ff901286f50fdcaa23189bd25a26f571637 }


condition:
	$a0
}