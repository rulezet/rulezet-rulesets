rule Win_Trojan_Saratoga_1
{
strings:
	$a0 = { 8bec50908cc0051000894604c746020000061e53515657b800008ec026803e3c03695f5e595b1f07585dcbb4 }


condition:
	$a0
}