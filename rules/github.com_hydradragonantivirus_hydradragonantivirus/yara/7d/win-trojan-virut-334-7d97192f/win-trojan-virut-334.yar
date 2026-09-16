rule Win_Trojan_Virut_334
{
strings:
	$a0 = { e8??000000[0-60]8a4500(f9|fc|66|eb|89|87|f8|f5|90)[0-25]884500[0-95]ffe7 }


condition:
	$a0
}