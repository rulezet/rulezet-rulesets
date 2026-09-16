rule Win_Trojan_Startpage_407
{
strings:
	$a0 = { 6a328d4db868541b400051ffd6506a01578d55bc68401b400052ffd6 }


condition:
	$a0
}