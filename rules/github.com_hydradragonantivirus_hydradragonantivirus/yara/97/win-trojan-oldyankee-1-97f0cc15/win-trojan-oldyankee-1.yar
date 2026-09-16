rule Win_Trojan_OldYankee_1
{
strings:
	$a0 = { f38cc089040e0753b8002fcd218bcb }


condition:
	$a0
}