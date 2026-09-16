rule Win_Trojan_Delf_2259
{
strings:
	$a0 = { 68d5024300e87e8c020068451a4300e8d18702007ddc7145df }

	$a1 = { 0a2a12324c4f41444552 }


condition:
	$a0 and $a1
}