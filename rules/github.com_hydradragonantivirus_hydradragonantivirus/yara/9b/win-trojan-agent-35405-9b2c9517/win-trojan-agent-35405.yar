rule Win_Trojan_Agent_35405
{
strings:
	$a0 = { 558bec83ec38297dd866c1a5d4ffffff1f8915913102107c0d8935ee30 }


condition:
	$a0
}