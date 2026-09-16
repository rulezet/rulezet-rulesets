rule Win_Trojan_Kremlin_2
{
strings:
	$a0 = { 8cca03d08cc981c1210651b90d00510606b1ff518cd383eb1853b14051fc8cd5be3c0033ff4d8ec58eda4ab908 }


condition:
	$a0
}