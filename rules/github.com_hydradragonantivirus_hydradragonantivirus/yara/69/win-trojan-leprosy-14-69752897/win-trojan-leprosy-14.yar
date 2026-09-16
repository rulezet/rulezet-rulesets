rule Win_Trojan_Leprosy_14
{
strings:
	$a0 = { 740ae8510046fe06f002eb08 }


condition:
	$a0
}