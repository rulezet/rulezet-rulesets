rule Win_Trojan_SillyC_207
{
strings:
	$a0 = { 2d84018bd0b440cd21b801578b4e028b5600cd21b43ecd21f89cb801438b56068e5e088b4e }


condition:
	$a0
}