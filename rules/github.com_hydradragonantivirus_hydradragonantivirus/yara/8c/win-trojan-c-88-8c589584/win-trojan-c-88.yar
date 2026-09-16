rule Win_Trojan_C_88
{
strings:
	$a0 = { 050050b8020050e8060583c40ab8290050b8aa0050b8010050e8c30d83c406faebfec3558bec83 }


condition:
	$a0
}