rule Win_Trojan_IRCBot_870
{
strings:
	$a0 = { 2a2a2a2a2a2a2a2a2a2a2a2a2a5b5343505d2a2a2a2a2a }


condition:
	$a0
}