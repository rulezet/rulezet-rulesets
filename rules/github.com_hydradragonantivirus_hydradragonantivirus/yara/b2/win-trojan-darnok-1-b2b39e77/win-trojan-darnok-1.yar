rule Win_Trojan_Darnok_1
{
strings:
	$a0 = { 8ec0bb007cb80102cd1307a14c00a33f02a14e00a34102b407cd1ab87d03 }


condition:
	$a0
}