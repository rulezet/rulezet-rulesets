rule Win_Trojan_Playgame_1
{
strings:
	$a0 = { d007b80102b90100ba8000cd13725d813f4d4b7457813fea0574518dbfbe01b304 }


condition:
	$a0
}