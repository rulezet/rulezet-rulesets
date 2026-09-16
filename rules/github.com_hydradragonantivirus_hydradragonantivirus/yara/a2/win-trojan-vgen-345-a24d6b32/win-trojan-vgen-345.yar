rule Win_Trojan_VGEN_345
{
strings:
	$a0 = { 01b99c00d1e973024146ad50e2fcffe48bf48d945e00b44eb92000cd217231eb09b44fba8000cd217226b8023d }


condition:
	$a0
}