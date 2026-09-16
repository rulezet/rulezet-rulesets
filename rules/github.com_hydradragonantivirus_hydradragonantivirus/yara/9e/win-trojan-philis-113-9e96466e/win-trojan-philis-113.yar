rule Win_Trojan_Philis_113
{
strings:
	$a0 = { 81c63139000081ee313900006081c63139000081ee313900 }


condition:
	$a0
}