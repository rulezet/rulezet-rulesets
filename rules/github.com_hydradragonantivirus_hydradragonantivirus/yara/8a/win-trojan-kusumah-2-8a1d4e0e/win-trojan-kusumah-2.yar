rule Win_Trojan_Kusumah_2
{
strings:
	$a0 = { 700f803e1201017503b99d0fba0001e8ad049ce850 }


condition:
	$a0
}