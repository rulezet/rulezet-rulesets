rule Win_Trojan_Pixel_33
{
strings:
	$a0 = { 45b42acd2180fa03753c33dbb003b91300cd2659ba }


condition:
	$a0
}