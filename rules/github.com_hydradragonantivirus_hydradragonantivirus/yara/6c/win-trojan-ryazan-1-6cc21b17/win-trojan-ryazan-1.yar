rule Win_Trojan_Ryazan_1
{
strings:
	$a0 = { b9ec011e8cc88ed880343e46e2fae80000 }


condition:
	$a0
}