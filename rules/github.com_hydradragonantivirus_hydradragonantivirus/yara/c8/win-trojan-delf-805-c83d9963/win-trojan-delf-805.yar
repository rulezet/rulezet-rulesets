rule Win_Trojan_Delf_805
{
strings:
	$a0 = { 8b95ecfbffff8d45f0b9a8654000e8d0ccffff6a008d85e8fbffffb9b46540008b55f0e8bbccffff8b85e8fbffffe85cceffff50e87adcffffb8dc654000e858f1ffff }


condition:
	$a0
}