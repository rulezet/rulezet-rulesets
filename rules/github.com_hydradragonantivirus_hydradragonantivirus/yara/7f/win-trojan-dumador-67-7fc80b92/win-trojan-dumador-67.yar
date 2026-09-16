rule Win_Trojan_Dumador_67
{
strings:
	$a0 = { 68a81000108b45b450e8a5fbffff50ff155410001085c07407b801000000 }


condition:
	$a0
}