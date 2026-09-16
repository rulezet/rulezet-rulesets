rule Win_Trojan_Traveller_1
{
strings:
	$a0 = { a3030029161200a112008ec00e1f8bde }


condition:
	$a0
}