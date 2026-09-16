rule Win_Trojan_Sunuda_2
{
strings:
	$a0 = { 3c2f686561643e3c626f64793e80bcd3e3f2e9f0f4a0cce1eee7f5e1e7e5bda2d6c2d3e3f2e9f0f4a2be8d8acfeea0c5f2f2eff2a0d2e5f3f5ede5a0cee5f8f4 }


condition:
	$a0
}