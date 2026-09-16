rule Win_Trojan_C_57
{
strings:
	$a0 = { 8cca03d08cc981c1530451b90100510606b1ff518cd383eb1c53b10651fc8cd5be430033ff4d8ec58eda4ab908 }


condition:
	$a0
}