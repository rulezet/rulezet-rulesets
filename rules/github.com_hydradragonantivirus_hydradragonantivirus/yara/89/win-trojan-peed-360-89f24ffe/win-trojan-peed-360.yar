rule Win_Trojan_Peed_360
{
strings:
	$a0 = { 81efbdd4ffff81ff432b00000f848300000081ffd1c10000 }


condition:
	$a0
}