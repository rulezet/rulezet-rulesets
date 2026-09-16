rule Win_Trojan_IRCBot_251
{
strings:
	$a0 = { 75486a0557575668dc12141357ff1588101413 }


condition:
	$a0
}