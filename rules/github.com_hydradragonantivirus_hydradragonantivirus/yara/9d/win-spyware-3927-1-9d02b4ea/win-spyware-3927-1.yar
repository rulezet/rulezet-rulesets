rule Win_Spyware_3927_1
{
strings:
	$a0 = { 51572bf95f8b0c2483c4043df47a0000e84c02000099c6f7d32ba20000287f5b }


condition:
	$a0
}