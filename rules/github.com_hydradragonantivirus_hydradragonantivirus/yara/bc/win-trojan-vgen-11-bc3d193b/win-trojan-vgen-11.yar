rule Win_Trojan_Vgen_11
{
strings:
	$a0 = { 1e06eb02eb0d8cc88ed82ec70603009090eb1eb88616cd2f0bc07402eb42b80a000e5bcd31501f803e30022a7c03e8 }


condition:
	$a0
}