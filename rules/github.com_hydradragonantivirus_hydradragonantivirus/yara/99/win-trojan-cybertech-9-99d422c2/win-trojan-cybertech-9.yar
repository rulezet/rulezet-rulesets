rule Win_Trojan_CyberTech_9
{
strings:
	$a0 = { ed0600508db61b008bfeb9f800ac342caae2fa02a7aa232d02a7b23d2d028f2c2d02a5322e2d9836962cd0 }


condition:
	$a0
}