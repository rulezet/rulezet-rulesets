rule Win_Trojan_Doom_3
{
strings:
	$a0 = { bf29012ea00b012e803e0a014574052e033e0301 }


condition:
	$a0
}