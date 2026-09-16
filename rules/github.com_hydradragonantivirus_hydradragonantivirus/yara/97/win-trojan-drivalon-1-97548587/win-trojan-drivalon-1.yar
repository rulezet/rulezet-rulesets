rule Win_Trojan_Drivalon_1
{
strings:
	$a0 = { 558bec6aff687015000168601d010164a100000000506489250000000083c4 }

	$a1 = { 526976616e6f6e }


condition:
	$a0 and $a1
}