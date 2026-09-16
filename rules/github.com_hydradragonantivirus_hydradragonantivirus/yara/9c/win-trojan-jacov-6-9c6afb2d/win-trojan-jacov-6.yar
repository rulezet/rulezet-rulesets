rule Win_Trojan_Jacov_6
{
strings:
	$a0 = { 8db617018bfeb9f200ad7304abe2fac335783b73f7 }


condition:
	$a0
}