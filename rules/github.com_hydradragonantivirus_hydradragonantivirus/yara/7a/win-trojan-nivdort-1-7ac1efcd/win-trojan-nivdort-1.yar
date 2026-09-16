rule Win_Trojan_Nivdort_1
{
strings:
	$a0 = { 506a006a02681001000068ff010f008b0d606e4f00518b15606e4f00528b45fc50ff15001a4f00 }


condition:
	$a0
}