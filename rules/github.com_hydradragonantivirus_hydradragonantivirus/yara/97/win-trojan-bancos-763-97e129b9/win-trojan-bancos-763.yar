rule Win_Trojan_Bancos_763
{
strings:
	$a0 = { 0b3c5316f13ea932741bfb6effb97923892811ee2daff55a4355f279a810c543fd542262fa8277b49a297f48cc2d4db2c9af410d7a7431dfe727c6b0f04904e24bfdc3b2 }


condition:
	$a0
}