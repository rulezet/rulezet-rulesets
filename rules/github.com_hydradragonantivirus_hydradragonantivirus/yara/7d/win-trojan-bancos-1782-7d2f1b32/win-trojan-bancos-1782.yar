rule Win_Trojan_Bancos_1782
{
strings:
	$a0 = { b387ae2f2646841aa64070b468cde5385cdc9c0acb37aae0e96093898d3aaf7abdfe43c3c1d92cc4f12c021e89774af34d788ced67f84915d3680acd1f41244188d6d4fbc7b9 }


condition:
	$a0
}