rule Win_Trojan_Snakebyte_1
{
strings:
	$a0 = { 9c60e800000000812c240720400058505d0bed741cb9e80400008d }


condition:
	$a0
}