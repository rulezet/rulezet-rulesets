rule Win_Trojan_Loader_2
{
strings:
	$a0 = { e5009a9206e5009a7702e500b001b9ff00ba0000cd26bf20021e57b02e5031c0509ad606 }


condition:
	$a0
}