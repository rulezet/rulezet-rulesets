rule Win_Trojan_Trojan_262
{
strings:
	$a0 = { ec00be700003f18a4c028a7403c3 }


condition:
	$a0
}