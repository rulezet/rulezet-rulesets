rule Win_Trojan_VGEN_363
{
strings:
	$a0 = { fcb90300bf00018db61e02f3a4b44eb906008d961302cd21721fe82100e85000e87400e88200e8a1008b9e1c02 }


condition:
	$a0
}