rule Win_Trojan_Grob_1
{
strings:
	$a0 = { 8902b8800287068400ab8cc887068600abb4019cff5f48 }


condition:
	$a0
}