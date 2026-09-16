rule Win_Trojan_SilverDollar_1
{
strings:
	$a0 = { b8030550e8eb0159e8a7000bc0740ae8680046fe062806eb08bab008b43bcd2146 }


condition:
	$a0
}