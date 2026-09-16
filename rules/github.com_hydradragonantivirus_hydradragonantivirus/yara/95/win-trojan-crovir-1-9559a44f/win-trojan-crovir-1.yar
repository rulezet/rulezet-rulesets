rule Win_Trojan_CroVir_1
{
strings:
	$a0 = { 4b74113d034b740c3daaff7403e9e800b8dcaccf9c55 }


condition:
	$a0
}