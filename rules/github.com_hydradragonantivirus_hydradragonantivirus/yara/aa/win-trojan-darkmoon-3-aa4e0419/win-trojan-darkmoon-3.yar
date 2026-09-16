rule Win_Trojan_Darkmoon_3
{
strings:
	$a0 = { 734b31614452396d4e3154497932744e33412f63454c4c616c }


condition:
	$a0
}