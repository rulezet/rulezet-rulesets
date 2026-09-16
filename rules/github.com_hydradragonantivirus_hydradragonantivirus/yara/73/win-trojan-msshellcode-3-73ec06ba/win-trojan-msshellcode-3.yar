rule Win_Trojan_MSShellcode_3
{
strings:
	$a0 = { fc33ff648b47308b400c8b581c8b1b8b7320adad4e03063d32335f3275ef8b6b088b453c8b4c05788b4c0d1c8b5c293c }


condition:
	$a0
}