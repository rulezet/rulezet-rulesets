rule Win_Trojan_Slod_1
{
strings:
	$a0 = { 74083cff7412cd10ebeeba0a00b9ffff4975fd4a75f7ebe0b002b90001ba0000bb0000cd26ebfe }


condition:
	$a0
}