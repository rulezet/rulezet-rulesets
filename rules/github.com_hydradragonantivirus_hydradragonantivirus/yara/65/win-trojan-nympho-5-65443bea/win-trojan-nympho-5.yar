rule Win_Trojan_Nympho_5
{
strings:
	$a0 = { 1303ba0001cd21e84700b440598bd6cd21268b4d0d268b550f5283e1e083e21f4a }


condition:
	$a0
}