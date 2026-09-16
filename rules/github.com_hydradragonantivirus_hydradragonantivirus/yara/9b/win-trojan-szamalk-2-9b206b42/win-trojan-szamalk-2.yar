rule Win_Trojan_Szamalk_2
{
strings:
	$a0 = { bf11018a04300546803c017503be1a074781ff1004 }


condition:
	$a0
}