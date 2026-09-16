rule Win_Trojan_ChDir_1
{
strings:
	$a0 = { 0300ba0802b440e83b00b800425a33c9cd21b44033d2b90b02e82900bd04032e8b56022e8b4e00 }


condition:
	$a0
}