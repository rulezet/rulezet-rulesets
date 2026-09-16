rule Win_Trojan_Jacov_8
{
strings:
	$a0 = { 8db617018bfeb9f300ad7304abe2fac335106b73f7 }


condition:
	$a0
}