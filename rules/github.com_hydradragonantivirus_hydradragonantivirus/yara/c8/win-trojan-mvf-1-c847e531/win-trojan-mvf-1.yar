rule Win_Trojan_Mvf_1
{
strings:
	$a0 = { a42f07a4423ca52e07970603bd1b14967e79cb0e3bc0cb5a03 }


condition:
	$a0
}