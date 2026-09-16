rule Win_Trojan_Jacov_17
{
strings:
	$a0 = { 8db617018bfeb96301ad7304abe2fac335000073f7 }


condition:
	$a0
}