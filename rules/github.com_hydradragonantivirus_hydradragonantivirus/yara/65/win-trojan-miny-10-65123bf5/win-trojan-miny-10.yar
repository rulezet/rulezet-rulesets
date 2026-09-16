rule Win_Trojan_Miny_10
{
strings:
	$a0 = { 02b80057cd215152b04033d2b99a02e82dffb000e8e000b040ba8802b90400e81dffb42ccd21 }


condition:
	$a0
}