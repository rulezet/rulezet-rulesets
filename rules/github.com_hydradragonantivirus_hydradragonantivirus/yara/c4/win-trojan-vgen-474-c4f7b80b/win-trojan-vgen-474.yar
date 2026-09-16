rule Win_Trojan_VGEN_474
{
strings:
	$a0 = { 8660058c8e68058c8e6c058c8e6405b42acd2180fa097536b4098d96f104cd2133c08ec0ba }


condition:
	$a0
}