rule Win_Spyware_Zbot_1276
{
strings:
	$a0 = { 6a4068??030000e8??fdffff83c4088985??feffff83bd??feffff00 }

	$a1 = { 8b????feffff89????ffffff[30-40]50ff95??ffffff }


condition:
	$a0 and $a1
}