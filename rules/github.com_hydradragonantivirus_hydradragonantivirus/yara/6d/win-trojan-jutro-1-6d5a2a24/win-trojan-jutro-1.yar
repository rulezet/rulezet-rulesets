rule Win_Trojan_Jutro_1
{
strings:
	$a0 = { 48015589e5b800049acd02480181ec000431c0a3c63431c0a3d434b00050bfc42f1e57b8ff00509ae30848018d }


condition:
	$a0
}