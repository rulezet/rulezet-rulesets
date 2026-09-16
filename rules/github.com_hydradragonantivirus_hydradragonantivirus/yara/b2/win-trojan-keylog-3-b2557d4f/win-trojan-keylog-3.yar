rule Win_Trojan_Keylog_3
{
strings:
	$a0 = { 7ffe0000ffff0001ffff8003ffffc007fffff83fff2406004b45594c4f4700260027[0-28]00746d724c4f4700 }


condition:
	$a0
}