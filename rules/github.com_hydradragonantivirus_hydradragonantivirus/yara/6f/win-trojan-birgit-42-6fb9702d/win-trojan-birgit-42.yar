rule Win_Trojan_Birgit_42
{
strings:
	$a0 = { 01b91c002e8ab649012e8a2732e62e882743e2f5c3 }


condition:
	$a0
}