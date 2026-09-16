rule Win_Trojan_Urkel_2
{
strings:
	$a0 = { db535eb8c0078ed8b8809f8ec08a0efc018a0483fe4b7e0432c188042688044681fefc0175eb }


condition:
	$a0
}