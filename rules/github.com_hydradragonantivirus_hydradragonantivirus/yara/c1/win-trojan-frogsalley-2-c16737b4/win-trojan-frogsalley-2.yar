rule Win_Trojan_FrogsAlley_2
{
strings:
	$a0 = { 0e8a600280ec048860024383fb4a75ee }


condition:
	$a0
}