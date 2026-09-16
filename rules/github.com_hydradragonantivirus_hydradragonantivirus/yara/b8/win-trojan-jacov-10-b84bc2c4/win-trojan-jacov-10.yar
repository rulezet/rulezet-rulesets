rule Win_Trojan_Jacov_10
{
strings:
	$a0 = { cf8db617018bfeb9fe00ad7304abe2fac335392173f7 }


condition:
	$a0
}