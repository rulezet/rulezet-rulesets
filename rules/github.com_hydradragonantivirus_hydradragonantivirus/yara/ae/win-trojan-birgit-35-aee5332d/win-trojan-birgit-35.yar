rule Win_Trojan_Birgit_35
{
strings:
	$a0 = { 01b941012e8ab66e022e8a2732e62e882743e2f5c3 }


condition:
	$a0
}