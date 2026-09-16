rule Win_Trojan_Salmon_1
{
strings:
	$a0 = { 8b3e????be0301b9f400313c4646e2fac3 }


condition:
	$a0
}