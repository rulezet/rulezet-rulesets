rule Win_Trojan_Acid_4
{
strings:
	$a0 = { 8cca03d08cc981c1c00151b90100510606b1ff518cd383eb1c53b10d51fc8cd5be380033ff4d8ec58eda4ab908 }


condition:
	$a0
}