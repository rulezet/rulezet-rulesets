rule Win_Trojan_Amoeba_2
{
strings:
	$a0 = { 9c502ea10701402ea307013d001072 }


condition:
	$a0
}