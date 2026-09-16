rule Win_Trojan_Comsysexe_2
{
strings:
	$a0 = { 0880fc4b7403eb0490e805002eff2eb3062e8926 }


condition:
	$a0
}