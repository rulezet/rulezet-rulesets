rule Win_Trojan_IRCBot_383
{
strings:
	$a0 = { e8f7feffff0567450000ffe0e8ebfeffff05946d0000ffe0e8f7010000e05749001106a54c4d2c1a29fa781e7d31a4fe }


condition:
	$a0
}