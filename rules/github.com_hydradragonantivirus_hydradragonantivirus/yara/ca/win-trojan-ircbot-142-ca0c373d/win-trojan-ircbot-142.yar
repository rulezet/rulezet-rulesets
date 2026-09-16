rule Win_Trojan_IRCBot_142
{
strings:
	$a0 = { 68340b4300e88c01000083c410e87f030000 }


condition:
	$a0
}