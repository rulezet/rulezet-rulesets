rule Win_Trojan_INT_3
{
strings:
	$a0 = { 210653268b4714a38002ff3680020726a10200a37a }


condition:
	$a0
}