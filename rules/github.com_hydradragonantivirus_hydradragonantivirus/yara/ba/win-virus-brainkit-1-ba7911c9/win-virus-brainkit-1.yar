rule Win_Virus_BrainKit_1
{
strings:
	$a0 = { 536154614e694320425261694e20564952555320544f4f4c53 }


condition:
	$a0
}