rule Win_Trojan_Lozinsky_1
{
strings:
	$a0 = { 5e2e8a44fcbf200003feb9cb032e300547e2fab8dd }


condition:
	$a0
}