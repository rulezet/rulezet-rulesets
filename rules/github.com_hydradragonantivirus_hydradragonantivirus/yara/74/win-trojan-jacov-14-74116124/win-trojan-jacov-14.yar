rule Win_Trojan_Jacov_14
{
strings:
	$a0 = { 8db617018bfeb90f01ad7304abe2fac3355d4d73f7 }


condition:
	$a0
}