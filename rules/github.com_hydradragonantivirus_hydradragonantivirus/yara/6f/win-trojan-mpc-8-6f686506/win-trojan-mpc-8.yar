rule Win_Trojan_MPC_8
{
strings:
	$a0 = { b42acd2180fe04721280fa03720d81f9c9077207b42ccd2180fa28b82425c596 }


condition:
	$a0
}