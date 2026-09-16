rule Win_Trojan_Level3_2
{
strings:
	$a0 = { 06c6996db90c3b1ea7fb3005f22c466a9ae989fb05936ba31d7bebef }


condition:
	$a0
}