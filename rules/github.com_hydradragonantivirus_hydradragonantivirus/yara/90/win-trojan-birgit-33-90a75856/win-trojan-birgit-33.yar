rule Win_Trojan_Birgit_33
{
strings:
	$a0 = { 1601b937012e8ab665022e8a2732e62e882743e2f5c3 }


condition:
	$a0
}