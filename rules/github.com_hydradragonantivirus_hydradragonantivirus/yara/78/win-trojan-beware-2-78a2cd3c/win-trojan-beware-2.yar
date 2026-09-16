rule Win_Trojan_Beware_2
{
strings:
	$a0 = { 7f02b43fb903008d958102cd217232 }


condition:
	$a0
}