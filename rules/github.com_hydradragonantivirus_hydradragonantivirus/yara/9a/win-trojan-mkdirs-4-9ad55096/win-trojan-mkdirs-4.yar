rule Win_Trojan_MkDirs_4
{
strings:
	$a0 = { 02be6902b90900fcac3492aa49e302ebf7ba4c01b41acd21b419cd218ad0fec2b447be0c01cd21ba0a01b43bcd21 }


condition:
	$a0
}