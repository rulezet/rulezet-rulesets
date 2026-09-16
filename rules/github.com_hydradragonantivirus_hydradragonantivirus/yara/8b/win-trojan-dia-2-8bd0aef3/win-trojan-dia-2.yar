rule Win_Trojan_Dia_2
{
strings:
	$a0 = { 0406579a7a08d2009a9102d20089ec5dc20400052a2e455845052a2e434f4d05446174653a21 }


condition:
	$a0
}