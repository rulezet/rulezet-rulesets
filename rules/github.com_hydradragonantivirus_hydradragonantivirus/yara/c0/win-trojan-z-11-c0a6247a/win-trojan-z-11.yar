rule Win_Trojan_Z_11
{
strings:
	$a0 = { c990cd21b440900e1f9090bafb5590b9f6449090cd2190b440905590901fba000190908bce9090 }


condition:
	$a0
}