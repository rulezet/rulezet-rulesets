rule Win_Trojan_FormatC_61
{
strings:
	$a0 = { 6e756c0000464f524d4154000920633a202f712f75 }


condition:
	$a0
}