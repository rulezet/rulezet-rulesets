rule Win_Trojan_DotKiller_3
{
strings:
	$a0 = { cd21b43ecd21b824252e8b161400 }


condition:
	$a0
}