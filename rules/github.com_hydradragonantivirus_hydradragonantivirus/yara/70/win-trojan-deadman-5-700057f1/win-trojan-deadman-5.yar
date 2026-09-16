rule Win_Trojan_Deadman_5
{
strings:
	$a0 = { b4408bcdcd21b440b954029099cd2133c87512909090b8004299cd21b440b11cba7f02cd215a }


condition:
	$a0
}