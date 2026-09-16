rule Win_Spyware_ye_210
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]cf1dd92eea893c6e10bde0caea8fc7 }


condition:
	$a0
}