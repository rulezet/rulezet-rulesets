rule Win_Trojan_Pirate_1
{
strings:
	$a0 = { 2104412ea2fc02b447b6002e8a16fc028d362903cd }


condition:
	$a0
}