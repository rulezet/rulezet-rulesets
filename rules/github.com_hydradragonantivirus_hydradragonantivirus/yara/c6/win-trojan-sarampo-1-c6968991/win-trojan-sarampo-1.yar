rule Win_Trojan_Sarampo_1
{
strings:
	$a0 = { 6f03b82125cd21b42acd2181fa1904740f81fa190c7409 }


condition:
	$a0
}