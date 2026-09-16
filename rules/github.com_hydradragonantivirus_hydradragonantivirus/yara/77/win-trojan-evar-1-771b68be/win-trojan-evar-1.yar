rule Win_Trojan_Evar_1
{
strings:
	$a0 = { e8000000005d81ed568541008bfd83ff00 }


condition:
	$a0
}