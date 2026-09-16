rule Win_Trojan_Sality_1018
{
strings:
	$a0 = { 558bec837d0800740e6a028b450850e80cffffff83c4085dc3 }


condition:
	$a0
}