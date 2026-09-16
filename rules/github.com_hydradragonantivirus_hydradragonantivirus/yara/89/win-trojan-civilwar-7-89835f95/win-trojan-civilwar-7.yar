rule Win_Trojan_CivilWar_7
{
strings:
	$a0 = { 023dba9e00cd2193b90500b43f8d969101cd2181be9401 }


condition:
	$a0
}