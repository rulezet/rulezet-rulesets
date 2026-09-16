rule Win_Trojan_Sality_1043
{
strings:
	$a0 = { 02c55f83c7018a44050087e43007515980e9015e4e0f85????0000 }


condition:
	$a0
}