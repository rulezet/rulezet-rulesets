rule Win_Trojan_RewriteBootA_1
{
strings:
	$a0 = { bb1401b001b403ba0000b90100cd13b8004ccd21b40eb043cd10ebfe }


condition:
	$a0
}