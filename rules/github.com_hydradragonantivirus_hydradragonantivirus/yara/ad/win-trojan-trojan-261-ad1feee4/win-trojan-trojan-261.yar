rule Win_Trojan_Trojan_261
{
strings:
	$a0 = { 8a0eeb00be700003f18a4c028a7403c3 }


condition:
	$a0
}