rule Win_Trojan_C_92
{
strings:
	$a0 = { 050050b8020050e8000583c40ab8290050b8aa0050b8010050e83b0e83c406faebfe5dc3558bec }


condition:
	$a0
}