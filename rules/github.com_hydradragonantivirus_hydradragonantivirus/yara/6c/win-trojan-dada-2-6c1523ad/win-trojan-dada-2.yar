rule Win_Trojan_DaDa_2
{
strings:
	$a0 = { 062e890e27062e891e29068cd82ea31d068cc8fa8e }


condition:
	$a0
}