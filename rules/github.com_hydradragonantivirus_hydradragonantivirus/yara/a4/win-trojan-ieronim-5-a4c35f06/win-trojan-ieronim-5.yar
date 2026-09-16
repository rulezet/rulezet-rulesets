rule Win_Trojan_Ieronim_5
{
strings:
	$a0 = { 51b9a03c81c164c62e813787f281c3437981eb4179e2f159c3 }


condition:
	$a0
}