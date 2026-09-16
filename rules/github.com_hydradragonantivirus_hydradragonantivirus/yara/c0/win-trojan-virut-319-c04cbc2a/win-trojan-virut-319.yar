rule Win_Trojan_Virut_319
{
strings:
	$a0 = { e8??000000[0-60]8a07(f9|fc|66|eb|89|87|f8|f5|90)[0-25]8607[0-95]ffe7 }


condition:
	$a0
}