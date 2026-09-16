rule Win_Trojan_Blood_2
{
strings:
	$a0 = { 02b40ecd21b41aba0c0003d5cd21ba040003d5b44e }


condition:
	$a0
}