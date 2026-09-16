rule Win_Trojan_Brain_1
{
strings:
	$a0 = { 4b0081c30002e2f4a113042d0700a313 }


condition:
	$a0
}