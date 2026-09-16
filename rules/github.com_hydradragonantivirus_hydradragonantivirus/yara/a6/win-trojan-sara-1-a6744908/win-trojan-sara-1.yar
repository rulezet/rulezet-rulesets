rule Win_Trojan_Sara_1
{
strings:
	$a0 = { 72615d21c8000100bfe7000e576a27bf964f1e579a88006c00833e1a52007403e9e200bfb44f }


condition:
	$a0
}