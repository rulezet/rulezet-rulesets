rule Win_Trojan_VGEN_401
{
strings:
	$a0 = { 5ab801faba4559cd16ba7701b44ecd21e83600ba7101b44ecd21e82c00b409ba2701cd21cd205061636b6564206669 }


condition:
	$a0
}