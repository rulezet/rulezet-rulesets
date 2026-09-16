rule Win_Trojan_Jerusalem_53
{
strings:
	$a0 = { e800005e8bde909081c61b00b990473680345446e2f981fb03007502eb36 }


condition:
	$a0
}