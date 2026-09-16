rule Win_Trojan_Leszop_1
{
strings:
	$a0 = { 1fc7060c7c62008c060e7cfbff2e0c7c }


condition:
	$a0
}