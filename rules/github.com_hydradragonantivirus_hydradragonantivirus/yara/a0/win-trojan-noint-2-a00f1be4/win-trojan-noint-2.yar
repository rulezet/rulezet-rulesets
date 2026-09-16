rule Win_Trojan_NoInt_2
{
strings:
	$a0 = { fa8000752983f901752451b90700b801029c2e }


condition:
	$a0
}