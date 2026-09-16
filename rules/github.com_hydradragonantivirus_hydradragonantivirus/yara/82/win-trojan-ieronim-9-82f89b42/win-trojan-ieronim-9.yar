rule Win_Trojan_Ieronim_9
{
strings:
	$a0 = { 7553061653561e5250518bd8b93e008bf28a0422c0 }


condition:
	$a0
}