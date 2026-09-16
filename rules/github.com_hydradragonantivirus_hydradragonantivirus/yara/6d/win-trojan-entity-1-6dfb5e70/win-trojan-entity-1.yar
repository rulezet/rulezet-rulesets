rule Win_Trojan_Entity_1
{
strings:
	$a0 = { e800005d81ed03018db61901b9d2032e8134000083c602e2f6 }


condition:
	$a0
}