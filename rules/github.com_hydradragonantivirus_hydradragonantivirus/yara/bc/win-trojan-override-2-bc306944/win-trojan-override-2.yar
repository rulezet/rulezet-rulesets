rule Win_Trojan_Override_2
{
strings:
	$a0 = { 01e8a500e89701bb0500b97005b440cd21e88a01e892 }


condition:
	$a0
}