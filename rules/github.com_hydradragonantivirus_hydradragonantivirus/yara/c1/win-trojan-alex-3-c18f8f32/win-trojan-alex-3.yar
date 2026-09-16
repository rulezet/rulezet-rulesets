rule Win_Trojan_Alex_3
{
strings:
	$a0 = { 5e1e0650510e5683c624bf3c008cc8408ec05057b90b0303f103f98cc88ed8fd41f3a4cb8cc88ed88f062d038f }


condition:
	$a0
}