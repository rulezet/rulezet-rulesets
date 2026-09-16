rule Win_Trojan_Termite_1
{
strings:
	$a0 = { 8cca03d08cc981c1a60551b90d00510606b1ff518cd383eb1853b14051fc8cd5be430033ff4d8ec58eda4ab908 }


condition:
	$a0
}