rule Win_Trojan_Ieronim_8
{
strings:
	$a0 = { fc4b7555061653561e5250518bd8b93e008bf28a0422c0 }


condition:
	$a0
}