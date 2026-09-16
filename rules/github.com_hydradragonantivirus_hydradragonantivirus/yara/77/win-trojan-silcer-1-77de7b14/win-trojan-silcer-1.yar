rule Win_Trojan_Silcer_1
{
strings:
	$a0 = { 444800000000400000000000 }

	$a1 = { 79204465766961746f722f2f48415a41524450b843dcf24758 }


condition:
	$a0 and $a1
}