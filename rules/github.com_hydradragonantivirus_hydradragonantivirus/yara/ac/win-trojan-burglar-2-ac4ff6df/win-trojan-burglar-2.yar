rule Win_Trojan_Burglar_2
{
strings:
	$a0 = { 81c79b03b90a00b87677902e31054790e2f958c390 }


condition:
	$a0
}