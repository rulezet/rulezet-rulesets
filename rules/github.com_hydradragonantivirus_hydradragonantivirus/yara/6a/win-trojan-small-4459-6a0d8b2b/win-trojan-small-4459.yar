rule Win_Trojan_Small_4459
{
strings:
	$a0 = { 8d0532??8303683255430350e84600000050 }


condition:
	$a0
}