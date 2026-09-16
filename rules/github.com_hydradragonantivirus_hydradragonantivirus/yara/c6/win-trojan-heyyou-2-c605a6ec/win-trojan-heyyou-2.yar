rule Win_Trojan_HeyYou_2
{
strings:
	$a0 = { 81f9c707721c80fe02721780fa19721233c08ec026f606 }


condition:
	$a0
}