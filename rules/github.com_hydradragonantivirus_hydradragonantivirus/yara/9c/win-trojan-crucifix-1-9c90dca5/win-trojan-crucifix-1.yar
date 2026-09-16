rule Win_Trojan_Crucifix_1
{
strings:
	$a0 = { 9ef3732205fdffa3cf01b9620bba0001b040e84900b84200e83b00b040bace01b90400e838008b }


condition:
	$a0
}