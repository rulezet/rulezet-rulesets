rule Win_Trojan_Capicua_1
{
strings:
	$a0 = { 99cd210ac07403e9b8012e8b2e010181c50203b44abb0010cd21b82135cd218bf581ee7401891c8c4402b80030cd21 }


condition:
	$a0
}