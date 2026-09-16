rule Win_Trojan_XM_1
{
strings:
	$a0 = { 33c08ed8ff366c04c70604006b01b8????2eff348f066c0431066c04ff366c042e8f044646d1c8ff0e040075e48f066c041fc3 }


condition:
	$a0
}