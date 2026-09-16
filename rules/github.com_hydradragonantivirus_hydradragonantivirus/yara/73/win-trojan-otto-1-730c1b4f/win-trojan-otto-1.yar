rule Win_Trojan_Otto_1
{
strings:
	$a0 = { e800005e5681ee0801582d0001a2ff0056b9600281c62501 }


condition:
	$a0
}