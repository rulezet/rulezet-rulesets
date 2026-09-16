rule Win_Trojan_Parasite_4
{
strings:
	$a0 = { 895c1d908c441f9007ebd0b42acd213c017d03eb4c }


condition:
	$a0
}