rule Win_Trojan_Vlad_4
{
strings:
	$a0 = { 3ec78613003ec7b80163cd213bc374438cc0488ed880 }


condition:
	$a0
}