rule Win_Trojan_Flip_8
{
strings:
	$a0 = { 0e1fb9209fb25081c1bf69eb0fce69ce69ce69ce69ce69ce69ce69ce0097391943eb }


condition:
	$a0
}