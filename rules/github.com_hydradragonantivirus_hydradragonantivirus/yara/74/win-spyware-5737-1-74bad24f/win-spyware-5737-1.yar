rule Win_Spyware_5737_1
{
strings:
	$a0 = { 535033c358515683c404e8fb000000 }


condition:
	$a0
}