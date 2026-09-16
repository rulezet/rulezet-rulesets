rule Win_Trojan_Shirley_4
{
strings:
	$a0 = { e90000b9eb09b805feebfc80c43bebf4bb1d010e07cd21b001cd21 }


condition:
	$a0
}