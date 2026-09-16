rule Win_Trojan_Idele_1
{
strings:
	$a0 = { 502d616469632076697275732076657273696f6e20 }


condition:
	$a0
}