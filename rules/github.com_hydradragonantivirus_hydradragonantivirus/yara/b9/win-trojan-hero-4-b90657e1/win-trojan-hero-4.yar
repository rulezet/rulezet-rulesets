rule Win_Trojan_Hero_4
{
strings:
	$a0 = { 80fc4b742080fc2575163c807212 }


condition:
	$a0
}