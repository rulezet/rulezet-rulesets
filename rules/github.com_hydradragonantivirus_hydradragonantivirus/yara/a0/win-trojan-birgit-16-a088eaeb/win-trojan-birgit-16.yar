rule Win_Trojan_Birgit_16
{
strings:
	$a0 = { 01b952002e8ab67e012e8a2732e62e882743e2f5c3 }


condition:
	$a0
}