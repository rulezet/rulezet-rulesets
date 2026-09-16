rule Win_Trojan_Mikrob_1
{
strings:
	$a0 = { 2812bd024233c999cd2f611fb4408d56fdb9ca00cd213e8b86e3002d04003e8986c5001e60b828 }


condition:
	$a0
}