rule Win_Trojan_Timeslice_2
{
strings:
	$a0 = { 1a09fa50d40ad50a58f3a4fbc38b77 }


condition:
	$a0
}