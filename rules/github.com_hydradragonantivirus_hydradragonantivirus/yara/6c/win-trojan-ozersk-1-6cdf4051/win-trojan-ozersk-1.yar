rule Win_Trojan_Ozersk_1
{
strings:
	$a0 = { 03b910008b1ea203b440cd21e8b200833ea203ff741f8b1ea203b43ecd218a0e8703b500b801 }


condition:
	$a0
}