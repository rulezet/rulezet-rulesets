rule Win_Trojan_Bolero_6
{
strings:
	$a0 = { 2e813dc3c3[0-15]03fdb2??2e30152e280d }


condition:
	$a0
}