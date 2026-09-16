rule Win_Trojan_Magick_2
{
strings:
	$a0 = { 06e800005a83c274b803250e1f3ecd21903ecc90071f8cdb83c310e800005e2e039ce401532effb4e60133c033db33 }


condition:
	$a0
}