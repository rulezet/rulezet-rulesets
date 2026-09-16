rule Win_Trojan_Mirea_5
{
strings:
	$a0 = { ee030160bad903ed0bc0750361cd2033c08ed88b0e0400b83412a304008b1e04003bc375e7890e04000e1f8b84b6 }


condition:
	$a0
}