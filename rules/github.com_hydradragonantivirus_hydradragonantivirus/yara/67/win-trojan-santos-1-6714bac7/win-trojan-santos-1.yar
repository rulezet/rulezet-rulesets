rule Win_Trojan_Santos_1
{
strings:
	$a0 = { 980480bfe3000075e3a0f504b400f7d81bc040bb030099f7fb0bd274586a00e8400859680401 }


condition:
	$a0
}