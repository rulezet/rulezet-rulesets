rule Win_Trojan_Creed_2
{
strings:
	$a0 = { 4b018cca03d08cc981c18b0351b90500510606b1ff518cd383eb1853b14051fc8cd5be3b0033ff4d8ec58eda4ab908 }


condition:
	$a0
}