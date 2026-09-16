rule Win_Trojan_Leprosy_6
{
strings:
	$a0 = { 7202b972018b166002b440cd21e8c600 }


condition:
	$a0
}