rule Win_Trojan_Ida_4
{
strings:
	$a0 = { 0172312d0300a3f801b44033d2b9b802e8d000b80042e8c300b440baf701b90300e8bf00b801 }


condition:
	$a0
}