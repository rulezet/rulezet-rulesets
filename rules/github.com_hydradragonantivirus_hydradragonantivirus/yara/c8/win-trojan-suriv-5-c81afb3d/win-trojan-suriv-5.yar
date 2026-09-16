rule Win_Trojan_Suriv_5
{
strings:
	$a0 = { 2acd2181f9c407720d81fa020874027205c6061e02 }


condition:
	$a0
}