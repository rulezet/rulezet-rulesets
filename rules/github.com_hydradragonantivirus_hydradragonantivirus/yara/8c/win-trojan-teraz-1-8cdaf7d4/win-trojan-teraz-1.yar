rule Win_Trojan_Teraz_1
{
strings:
	$a0 = { b459a32b1548c18f0fafba2ba6888c6fef12d8c82116ab40d7af1be0f47bd80a34c4906c846574e2 }


condition:
	$a0
}