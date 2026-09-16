rule Win_Trojan_Wind_1
{
strings:
	$a0 = { b000e88600b120b440cd21810612000101b440b97001cd21b054b503f2ae813d686975f84f57b8 }


condition:
	$a0
}