rule Win_Trojan_Itti_2
{
strings:
	$a0 = { 15b77eb92700ba8c01cd217215e81d007504b44febf3b4 }


condition:
	$a0
}