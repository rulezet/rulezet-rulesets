rule Win_Trojan_Carriers_1
{
strings:
	$a0 = { d4a858901cdcaaae48b0a25dbfe348a6a2b61aad5dbfebb656d59292b686d5951005e1b61bd5b8b6 }


condition:
	$a0
}