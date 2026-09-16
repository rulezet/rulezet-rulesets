rule Win_Trojan_Kobain_1
{
strings:
	$a0 = { e800005e81ee0301b8cabacd213dbaca7508bfb704 }


condition:
	$a0
}