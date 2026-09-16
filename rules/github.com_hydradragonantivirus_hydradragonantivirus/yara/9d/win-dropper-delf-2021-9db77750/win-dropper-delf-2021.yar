rule Win_Dropper_Delf_2021
{
strings:
	$a0 = { ba908f4100a138c94100e84ff5ffff8b45ece833eafeffa3a0ca4100833da0ca4100020f8dc50100006898c941006800010000e876d5feff }


condition:
	$a0
}