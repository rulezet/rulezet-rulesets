rule Win_Trojan_Jacov_13
{
strings:
	$a0 = { cf8db617018bfeb90101ad7304abe2fac335573973f7 }


condition:
	$a0
}