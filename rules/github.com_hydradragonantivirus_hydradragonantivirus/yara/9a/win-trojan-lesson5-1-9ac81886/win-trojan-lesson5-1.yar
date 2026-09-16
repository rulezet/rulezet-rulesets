rule Win_Trojan_Lesson5_1
{
strings:
	$a0 = { 6a02908d940001e85301b8420033c933d2e84901b040b918008d944f02e83d01b03ee83801 }


condition:
	$a0
}