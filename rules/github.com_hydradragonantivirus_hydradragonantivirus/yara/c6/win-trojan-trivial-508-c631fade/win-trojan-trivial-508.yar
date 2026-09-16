rule Win_Trojan_Trivial_508
{
strings:
	$a0 = { 5ab801faba4559cd16ba5701b44ecd21e84900ba5101b44ecd21e83f00b409ba2701cd21cd20546869732070726f67 }


condition:
	$a0
}