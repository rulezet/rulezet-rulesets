rule Win_Trojan_Birgit_37
{
strings:
	$a0 = { 01b964012e8ab691022e8a2732e62e882743e2f5c3 }


condition:
	$a0
}