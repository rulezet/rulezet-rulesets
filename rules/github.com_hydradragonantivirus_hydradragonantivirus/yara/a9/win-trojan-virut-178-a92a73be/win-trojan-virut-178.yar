rule Win_Trojan_Virut_178
{
strings:
	$a0 = { e8??000000[0-100]8603(f9|fc|66|eb|89|87|f8|f5|90)[0-15]8603c3 }


condition:
	$a0
}