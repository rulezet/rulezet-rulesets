rule Win_Trojan_Yankee_17
{
strings:
	$a0 = { 83c4049e7303e9f002b8004233c933d28b1e3c00e827ff }


condition:
	$a0
}