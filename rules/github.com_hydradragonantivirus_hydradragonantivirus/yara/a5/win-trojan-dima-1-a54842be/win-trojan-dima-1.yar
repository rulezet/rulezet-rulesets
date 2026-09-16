rule Win_Trojan_Dima_1
{
strings:
	$a0 = { 2e044f4d74452bc92bd2b80242cd212e83861c040772 }


condition:
	$a0
}