rule Win_Trojan_Trivial_429
{
strings:
	$a0 = { cd2180fe07743580fe087430b44eb120baa701cd21b8013dba9e00cd218bd8ba0001b9fa00b440cd21b43ecd21b4 }


condition:
	$a0
}