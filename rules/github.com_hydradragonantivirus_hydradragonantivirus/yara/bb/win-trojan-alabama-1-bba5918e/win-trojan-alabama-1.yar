rule Win_Trojan_Alabama_1
{
strings:
	$a0 = { 8edbffb79000ffb79200c787900072028c8f9200 }


condition:
	$a0
}