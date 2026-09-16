rule Win_Trojan_R_3
{
strings:
	$a0 = { 3deeef7505e88e0158cf3d004c745b80fc3e745680 }


condition:
	$a0
}