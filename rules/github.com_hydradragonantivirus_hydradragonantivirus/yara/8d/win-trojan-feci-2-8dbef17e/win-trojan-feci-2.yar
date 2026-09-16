rule Win_Trojan_Feci_2
{
strings:
	$a0 = { 22015589e5b800089acd02220181ec00088dbe00ff1657b80100509a60092201bf960e0e579aee0b2201750cc7 }


condition:
	$a0
}