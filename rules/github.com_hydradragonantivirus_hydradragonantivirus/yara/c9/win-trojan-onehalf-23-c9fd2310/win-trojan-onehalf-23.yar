rule Win_Trojan_OneHalf_23
{
strings:
	$a0 = { 21b8717b6a48492263ac2c4eba0d131c863f71bd20b5b56e6eb7 }


condition:
	$a0
}