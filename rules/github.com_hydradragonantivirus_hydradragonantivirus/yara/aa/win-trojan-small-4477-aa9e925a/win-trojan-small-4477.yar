rule Win_Trojan_Small_4477
{
strings:
	$a0 = { 8b44241c8d8032cb8303683255430350e8470000004050ba42b8ec0e52505155 }


condition:
	$a0
}