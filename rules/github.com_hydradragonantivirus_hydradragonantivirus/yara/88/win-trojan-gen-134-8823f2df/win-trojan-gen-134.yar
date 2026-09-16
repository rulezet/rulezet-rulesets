rule Win_Trojan_Gen_134
{
strings:
	$a0 = { c703532effb55d04bbde03b97f0058 }


condition:
	$a0
}