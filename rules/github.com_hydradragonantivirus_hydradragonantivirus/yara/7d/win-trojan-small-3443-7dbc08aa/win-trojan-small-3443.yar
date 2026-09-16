rule Win_Trojan_Small_3443
{
strings:
	$a0 = { 68507b40006830704000e80c000000595933c0c3 }


condition:
	$a0
}