rule Win_Trojan_Lozinsky_2
{
strings:
	$a0 = { 200003feb9d0032e300547e2fab8 }


condition:
	$a0
}