rule Win_Trojan_Peed_197
{
strings:
	$a0 = { 558bec83ec1c5356578bf5f7d3f7db33fdf7df85fb4f03dbc745f83f12400043400fbed94a2b }


condition:
	$a0
}