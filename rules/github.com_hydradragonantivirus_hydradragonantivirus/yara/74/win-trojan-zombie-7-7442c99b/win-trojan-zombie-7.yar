rule Win_Trojan_Zombie_7
{
strings:
	$a0 = { 0e1ffcb088e688e4883488bfeb0300054781fff90a7302ebf5b42acd213ad67503e9b900b85757bb7b05cd213d }


condition:
	$a0
}