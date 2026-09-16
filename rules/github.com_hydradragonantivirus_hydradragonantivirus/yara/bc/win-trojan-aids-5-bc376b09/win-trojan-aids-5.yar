rule Win_Trojan_AIDS_5
{
strings:
	$a0 = { 5589e581ec0202bfca050e57bf3e }


condition:
	$a0
}