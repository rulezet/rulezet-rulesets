rule Win_Trojan_Chin_1
{
strings:
	$a0 = { e8e700720bb440ba1000b91a00e8da0072123bc1753c8b0e2f008b162d00b80042e8c60072 }


condition:
	$a0
}