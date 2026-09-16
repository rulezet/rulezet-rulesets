rule Win_Trojan_Spectre_1
{
strings:
	$a0 = { 7c24508d866cff50e8671e83c406b88724508d866cff50e8730559598bf8b88a245057e8c517 }


condition:
	$a0
}