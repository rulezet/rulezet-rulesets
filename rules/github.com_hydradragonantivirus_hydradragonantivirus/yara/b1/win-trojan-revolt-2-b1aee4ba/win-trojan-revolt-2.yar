rule Win_Trojan_Revolt_2
{
strings:
	$a0 = { 558bec33f84f0bf90bf80bf203d98bf703f803d84681f9b8b948f85159e9000000000f85e3fcffff74ffe87425258b }


condition:
	$a0
}