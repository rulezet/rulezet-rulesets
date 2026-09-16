rule Win_Trojan_TwoMinutes_1
{
strings:
	$a0 = { 2acd21c784e6024f4dc684e3022ac684e8020080fa1f75 }


condition:
	$a0
}