rule Win_Trojan_Corea_3
{
strings:
	$a0 = { 0301eb039000008a26a003eb03900000b99d02eb029000aceb0290 }


condition:
	$a0
}