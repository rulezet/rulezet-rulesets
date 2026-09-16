rule Win_Trojan_V_17
{
strings:
	$a0 = { 2e05794f4f3d3ed66262d6d21f05857f7e0b03807b7b0f0ce4d1d15d9e1ddecee0e1ffc9c9e7467c7c7fbc32e2cc47 }


condition:
	$a0
}