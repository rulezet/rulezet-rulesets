rule Win_Trojan_W95APP_1
{
strings:
	$a0 = { 04000000eb39be05000000eb326681bdf0feffff4e45721c76d76681bdf0feffff5045721a76d1 }


condition:
	$a0
}