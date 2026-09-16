rule Win_Trojan_Timid_1
{
strings:
	$a0 = { 1644ff81c252008b1e55ffb80042cd21b90500 }


condition:
	$a0
}