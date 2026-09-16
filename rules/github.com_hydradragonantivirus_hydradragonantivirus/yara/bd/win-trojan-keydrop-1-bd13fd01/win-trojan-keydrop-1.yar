rule Win_Trojan_KeyDrop_1
{
strings:
	$a0 = { be5d01ac0ac0750832e4cd16cd19ebdb }


condition:
	$a0
}