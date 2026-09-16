rule Win_Trojan_bat_2
{
strings:
	$a0 = { 666f726d617420633a202f6175746f74657374202f71202f75 }


condition:
	$a0
}