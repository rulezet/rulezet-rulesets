rule Win_Trojan_Burglar_4
{
strings:
	$a0 = { 03042e8ba4050433c033db2effac09045081c70304b90a00b87677902e31054790e2f958c3 }


condition:
	$a0
}