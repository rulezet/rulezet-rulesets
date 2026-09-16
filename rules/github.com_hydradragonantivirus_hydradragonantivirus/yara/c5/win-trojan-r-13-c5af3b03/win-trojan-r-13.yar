rule Win_Trojan_R_13
{
strings:
	$a0 = { 02b4408d960001cd21b8004233c999cd21b91a00b4408d961203cd21b43ecd21b44feba1b42a }


condition:
	$a0
}