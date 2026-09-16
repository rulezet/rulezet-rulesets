rule Win_Trojan_N_24
{
strings:
	$a0 = { 2e8b1e9d04e8bcffb440b91800ba0d04e8b1ffc30633c08ec026a19000268b0e92002ea39904 }


condition:
	$a0
}