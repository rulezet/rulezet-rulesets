rule Win_Trojan_Codewar_2
{
strings:
	$a0 = { 95dfdfa92356534043ab73c2859865cd5268dd1fcbd9b8 }


condition:
	$a0
}