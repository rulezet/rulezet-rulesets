rule Win_Spyware_Banker_2714
{
strings:
	$a0 = { da0283dfef620b127d43fced262c6003ae5e346106a763cada2c828c070fdc9ddfea825d726884d890d2ebcf735c41176f5bb9add6d1b27cb71f4debb32b02792be2c05a34b3a457d8ebac7e3e81 }


condition:
	$a0
}