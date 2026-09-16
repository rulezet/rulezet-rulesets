rule Win_Trojan_Virut_92
{
strings:
	$a0 = { e8??000000[0-50]8a02(f9|fc|66|eb|89|87|f8|f5|90)[0-15]8602[0-50]ffe3 }


condition:
	$a0
}