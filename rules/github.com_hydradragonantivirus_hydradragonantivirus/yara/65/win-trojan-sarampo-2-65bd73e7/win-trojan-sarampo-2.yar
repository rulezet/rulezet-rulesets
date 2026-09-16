rule Win_Trojan_Sarampo_2
{
strings:
	$a0 = { 2125cd21b42acd2181fa1904740f81fa190c7409 }


condition:
	$a0
}