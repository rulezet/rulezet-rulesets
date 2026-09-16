rule Win_Trojan_Kaczor_5
{
strings:
	$a0 = { 3400802eff062100902e813e2100571175eb90 }


condition:
	$a0
}