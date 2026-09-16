rule Win_Trojan_Ace_4
{
strings:
	$a0 = { 3e0101b419cd213c027210b44abbffffcd2181fb01107203eb0b90e91601416365312e30e1b41abaafffcd21c685 }


condition:
	$a0
}