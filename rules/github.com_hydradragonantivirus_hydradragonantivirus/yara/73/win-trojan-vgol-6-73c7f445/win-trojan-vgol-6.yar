rule Win_Trojan_VGOL_6
{
strings:
	$a0 = { b44031d2b95007e8e5fa3d50077526803e50074db90700baf504b4407402cd21b8004231d2 }


condition:
	$a0
}