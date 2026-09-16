rule Win_Trojan_IRCBot_286
{
strings:
	$a0 = { 76696c6e756c660965ff9ffdff732e73657276656674702e6e65744c6d4952 }


condition:
	$a0
}