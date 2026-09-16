rule Win_Trojan_Pixel_35
{
strings:
	$a0 = { 35b010cd21891e3c018c063e01b435b01ccd21891e38018c063a01268a47ff3c247424b425b01cba0801cd21ba }


condition:
	$a0
}