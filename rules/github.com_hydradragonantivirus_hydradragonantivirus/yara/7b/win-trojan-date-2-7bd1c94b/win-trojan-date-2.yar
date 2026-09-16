rule Win_Trojan_Date_2
{
strings:
	$a0 = { 010100558e01000000ffff5e03000012040000030000005e03 }


condition:
	$a0
}