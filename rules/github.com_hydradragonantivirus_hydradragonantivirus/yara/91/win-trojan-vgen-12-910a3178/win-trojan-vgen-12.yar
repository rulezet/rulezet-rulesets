rule Win_Trojan_Vgen_12
{
strings:
	$a0 = { eb02eb0d8cc88ed82ec70603009090eb1eb88616cd2f0bc07402eb42b80a000e5bcd31501f803e3002647c03e8 }


condition:
	$a0
}