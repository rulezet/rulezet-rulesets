rule Win_Trojan_Nexiv_Der_3
{
strings:
	$a0 = { 77d81e29b14aef94cb79ea9f131410eb1ac57f0fed20bac1 }


condition:
	$a0
}