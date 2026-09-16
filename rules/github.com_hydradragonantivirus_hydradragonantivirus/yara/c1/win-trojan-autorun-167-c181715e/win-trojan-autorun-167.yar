rule Win_Trojan_Autorun_167
{
strings:
	$a0 = { ba5c9b14138d8520feffffe81b92ffff8d8520feffffe8ac8fffffe8738dffffba709b14138d8520feffffe8cfa8ffffe81e95ffff }


condition:
	$a0
}