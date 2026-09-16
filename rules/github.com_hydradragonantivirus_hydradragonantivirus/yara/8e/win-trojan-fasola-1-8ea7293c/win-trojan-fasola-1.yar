rule Win_Trojan_Fasola_1
{
strings:
	$a0 = { 1e068e1e2c00ac3c0075fbac3c00741f3c4a75f2ad3d415275ecad3d454b75e6ad3d3d4f75e0ad3d464675dae92502 }


condition:
	$a0
}