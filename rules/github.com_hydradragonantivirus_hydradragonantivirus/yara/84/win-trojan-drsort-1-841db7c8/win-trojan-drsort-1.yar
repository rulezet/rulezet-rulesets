rule Win_Trojan_DrSort_1
{
strings:
	$a0 = { 03030e5731c0509a780862009ab00762009a0e026200bff4011e57bf2c030e5731c0509a780862 }


condition:
	$a0
}