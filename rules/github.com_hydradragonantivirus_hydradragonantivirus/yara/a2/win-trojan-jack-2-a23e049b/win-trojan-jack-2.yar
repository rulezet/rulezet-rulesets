rule Win_Trojan_Jack_2
{
strings:
	$a0 = { 02000e1f5ead3d4d5a74183d5a4d74138bdc1653bf00010657aba583c606bd4558eb108cc383c3 }


condition:
	$a0
}