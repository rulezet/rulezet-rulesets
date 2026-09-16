rule Win_Trojan_Kremlin_1
{
strings:
	$a0 = { 8cca03d08cc981c1db0551b90d00510606b1ff518cd383eb1853b14051fc8cd5be460033ff4d8ec58eda4ab908 }


condition:
	$a0
}