rule Win_Trojan_Birgit_44
{
strings:
	$a0 = { 1801b92a002e8ab65a012e8a2732e62e882743e2f5c3 }


condition:
	$a0
}