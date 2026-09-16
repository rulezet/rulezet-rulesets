rule Win_Trojan_IRC_Script_28
{
strings:
	$a0 = { 73617920[0-10]2024646c6c286b6f72652e646c6c2c }


condition:
	$a0
}