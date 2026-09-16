rule Win_Trojan_VGEN_74
{
strings:
	$a0 = { 9a00008c009a00002a005589e59ac2012a00b008b9ff00ba0000cd26bf52011e57b02e5031c0509a0c068c009ac8058c }


condition:
	$a0
}