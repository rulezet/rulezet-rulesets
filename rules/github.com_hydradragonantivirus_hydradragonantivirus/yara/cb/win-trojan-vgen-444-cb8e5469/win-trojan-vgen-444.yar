rule Win_Trojan_VGEN_444
{
strings:
	$a0 = { ba4559cd215a58b44a33dbcd21b44abbffffcd2181eb0101b44acd21b448bb0001cd218ec006 }


condition:
	$a0
}