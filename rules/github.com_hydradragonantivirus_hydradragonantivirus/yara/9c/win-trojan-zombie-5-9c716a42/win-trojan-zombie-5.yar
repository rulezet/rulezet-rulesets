rule Win_Trojan_Zombie_5
{
strings:
	$a0 = { f0bfff8d9528104000b970040000f71a81325a1bc03683eafce2f3eb0387db90 }


condition:
	$a0
}