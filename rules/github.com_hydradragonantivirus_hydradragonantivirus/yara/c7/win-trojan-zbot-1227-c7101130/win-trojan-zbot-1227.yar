rule Win_Trojan_Zbot_1227
{
strings:
	$a0 = { 558bec83c4f0535657b8e41f4000e831f9ffff33c05568f923400064 }

	$a1 = { 495241484f0c454c4300 }


condition:
	$a0 and $a1
}