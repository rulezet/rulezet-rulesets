rule Win_Trojan_Maljava_4
{
strings:
	$a0 = { 6a6176617570646174652f5061796c6f6164 }

	$a1 = { 646f50726976696c65676564 }


condition:
	$a0 and $a1
}