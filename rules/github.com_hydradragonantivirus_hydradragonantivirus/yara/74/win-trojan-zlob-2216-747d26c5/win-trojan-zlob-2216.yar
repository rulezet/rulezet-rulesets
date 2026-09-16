rule Win_Trojan_Zlob_2216
{
strings:
	$a0 = { 67617262616765776f726c64 }

	$a1 = { 414e584743415847424558444240 }

	$a2 = { 7765777425642e626174 }


condition:
	$a0 and $a1 and $a2
}