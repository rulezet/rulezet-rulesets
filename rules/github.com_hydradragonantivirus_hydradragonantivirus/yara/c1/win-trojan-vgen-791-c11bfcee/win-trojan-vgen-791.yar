rule Win_Trojan_VGEN_791
{
strings:
	$a0 = { 08008eda8cd32bdad1e3d1e3d1e3d1e3fa8ed203e3fb06b40fcd103c077405b800b8eb03b800b08ec02bf6be00002b }


condition:
	$a0
}