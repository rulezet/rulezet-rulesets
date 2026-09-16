rule Win_Trojan_Jacov_15
{
strings:
	$a0 = { 03cf8db617018bfeb96101ad7304abe2fac335645973f7 }


condition:
	$a0
}