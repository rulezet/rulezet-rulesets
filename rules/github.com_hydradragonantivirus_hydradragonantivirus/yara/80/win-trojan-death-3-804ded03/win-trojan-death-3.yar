rule Win_Trojan_Death_3
{
strings:
	$a0 = { 8c064301ba1a01b425cd21b245cd27200160b002e640b003e640bada03ecb2c0b033ee2e }


condition:
	$a0
}