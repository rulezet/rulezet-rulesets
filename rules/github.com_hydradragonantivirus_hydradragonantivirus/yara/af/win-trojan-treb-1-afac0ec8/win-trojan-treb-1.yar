rule Win_Trojan_Treb_1
{
strings:
	$a0 = { 3d88b03703c9f88d3d424b36056cff6c4f42e8c604449c22 }


condition:
	$a0
}