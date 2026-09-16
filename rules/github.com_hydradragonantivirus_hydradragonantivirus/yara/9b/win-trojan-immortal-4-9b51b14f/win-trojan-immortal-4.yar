rule Win_Trojan_Immortal_4
{
strings:
	$a0 = { 02397d2574198d76fdb916012ef3a4bf5603be840056a5a55fb8f302ab91ab }


condition:
	$a0
}