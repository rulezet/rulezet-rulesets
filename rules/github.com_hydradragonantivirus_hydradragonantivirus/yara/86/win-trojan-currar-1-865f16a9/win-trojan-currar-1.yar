rule Win_Trojan_Currar_1
{
strings:
	$a0 = { cd218ad00633c08ec02638163c05751b07b42acd2180fa05750e80fe077509b409ba3402cd21cd20e9b60207b447 }


condition:
	$a0
}