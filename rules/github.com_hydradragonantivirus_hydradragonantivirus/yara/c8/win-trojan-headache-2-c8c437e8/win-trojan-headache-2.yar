rule Win_Trojan_Headache_2
{
strings:
	$a0 = { 01018a27bb02018a0786c48bf0b41a8d94c802cd2133c9 }


condition:
	$a0
}