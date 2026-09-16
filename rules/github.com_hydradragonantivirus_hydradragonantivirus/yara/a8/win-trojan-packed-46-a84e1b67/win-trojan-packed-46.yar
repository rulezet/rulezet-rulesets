rule Win_Trojan_Packed_46
{
strings:
	$a0 = { 0fabc1f284f189cb23cf8d3d }


condition:
	$a0
}