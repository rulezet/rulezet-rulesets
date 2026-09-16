rule Win_Trojan_AIDS_6
{
strings:
	$a0 = { 89e581ec0202bfca050e57bf3e011e }


condition:
	$a0
}