rule Win_Trojan_Brasil_1
{
strings:
	$a0 = { 565656000000434f4d4d414e442e434f4d002a2e434f4d }


condition:
	$a0
}