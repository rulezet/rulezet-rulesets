rule Win_Trojan_Jacov_9
{
strings:
	$a0 = { 8db617018bfeb9f400ad7304abe2fac3352b6173f7 }


condition:
	$a0
}