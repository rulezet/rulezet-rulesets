rule Win_Trojan_Birgit_39
{
strings:
	$a0 = { 01b97e012e8ab6ab022e8a2732e62e882743e2f5c3 }


condition:
	$a0
}