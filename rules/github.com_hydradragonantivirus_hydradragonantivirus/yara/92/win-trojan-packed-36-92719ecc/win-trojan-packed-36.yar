rule Win_Trojan_Packed_36
{
strings:
	$a0 = { 0f6eee9060bb }


condition:
	$a0
}