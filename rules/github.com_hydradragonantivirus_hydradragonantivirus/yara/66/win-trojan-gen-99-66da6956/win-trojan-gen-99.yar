rule Win_Trojan_Gen_99
{
strings:
	$a0 = { 2ea302018c1e2200c70620008800 }


condition:
	$a0
}