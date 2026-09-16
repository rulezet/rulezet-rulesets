rule Win_Trojan_Hupigon_69
{
strings:
	$a0 = { 85c00f84020200006878214a006aff6a00e8e74ef6ff }


condition:
	$a0
}