rule Win_Trojan_Vgen_71
{
strings:
	$a0 = { 5f505eb8ae0003f0b803002bf803f08b048905464647478a048805b805002bf08bfeb8060003f8b44e33c98bd7cd21 }


condition:
	$a0
}