rule Win_Trojan_Pit_2
{
strings:
	$a0 = { 4333c9bafc01cd21b441bafc01cd21b44ebaf60133c9 }


condition:
	$a0
}