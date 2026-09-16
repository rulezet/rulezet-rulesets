rule Win_Trojan_IRC_Script_25
{
strings:
	$a0 = { 3d25626f746c6f676f20 }

	$a1 = { 3d255f7061636b6574696e67 }


condition:
	$a0 and $a1
}