rule Win_Trojan_DG_2
{
strings:
	$a0 = { 40ba050103d68b9c5c028b8c8502cd21b43e8b9c5c02cd }


condition:
	$a0
}