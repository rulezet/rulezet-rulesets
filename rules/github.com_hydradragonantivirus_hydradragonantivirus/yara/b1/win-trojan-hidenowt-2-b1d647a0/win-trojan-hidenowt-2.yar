rule Win_Trojan_Hidenowt_2
{
strings:
	$a0 = { 9c5825fff8509de40100200000000043e85301c1f8e5 }


condition:
	$a0
}