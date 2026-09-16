rule Win_Trojan_Jerusulem_1
{
strings:
	$a0 = { 05e0f98bd783c203b8004b061f0e07bb35001e065053 }


condition:
	$a0
}