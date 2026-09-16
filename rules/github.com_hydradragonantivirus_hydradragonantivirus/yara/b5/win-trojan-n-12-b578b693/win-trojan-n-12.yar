rule Win_Trojan_N_12
{
strings:
	$a0 = { 8ec0bf000089feb96601f3a5061f33ede87400b440b9cb02ba0000cd21b800429933c9cd21b440 }


condition:
	$a0
}