rule Win_Trojan_Sahra_2
{
strings:
	$a0 = { 5c5c78666972655c5c646f776e6c6f616473222b526e64696e6c6f766573 }


condition:
	$a0
}