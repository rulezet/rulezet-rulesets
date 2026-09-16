rule Win_Trojan_Delta_II_1
{
strings:
	$a0 = { ee03c604e98944018bd6b440b90300cd21f8c353c606aa030290a10204a38e00a104040510 }


condition:
	$a0
}