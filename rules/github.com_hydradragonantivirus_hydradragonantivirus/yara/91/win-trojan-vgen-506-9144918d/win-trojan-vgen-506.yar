rule Win_Trojan_VGEN_506
{
strings:
	$a0 = { ba0000311483c2004646e2f75a59c3b440cd21c38bd0b800427305fec0fec09933c9cd21c3 }


condition:
	$a0
}