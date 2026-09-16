rule Win_Trojan_bat_1
{
strings:
	$a0 = { 40666f726d617420633a2f206175746f74657374 }


condition:
	$a0
}