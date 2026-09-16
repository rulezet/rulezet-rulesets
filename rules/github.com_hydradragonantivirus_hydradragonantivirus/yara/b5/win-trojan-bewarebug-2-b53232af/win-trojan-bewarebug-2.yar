rule Win_Trojan_BewareBug_2
{
strings:
	$a0 = { 01b43ffec4ba6f01b988059c2eff1e2e01b43ffec4baf706b96f009c2eff1e2e01b80057 }


condition:
	$a0
}