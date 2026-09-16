rule Win_Trojan_Zombie_10
{
strings:
	$a0 = { 3d004b740f3d694b74069d2eff2e84008bd89dcf2ec706 }


condition:
	$a0
}