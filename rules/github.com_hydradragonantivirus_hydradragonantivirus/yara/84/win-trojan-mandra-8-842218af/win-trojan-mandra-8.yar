rule Win_Trojan_Mandra_8
{
strings:
	$a0 = { bd45b873b7bba27fb8475030bd73d1bc6efa87db19c1e081ffcfbabae081ffd1baba6efa4750e8bd }


condition:
	$a0
}