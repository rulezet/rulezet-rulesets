rule Win_Trojan_Rape_19
{
strings:
	$a0 = { 81ee170b8bfe57501e060e1f0e07b62b }


condition:
	$a0
}