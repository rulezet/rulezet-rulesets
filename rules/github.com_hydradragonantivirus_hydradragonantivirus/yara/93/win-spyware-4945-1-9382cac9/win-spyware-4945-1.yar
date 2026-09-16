rule Win_Spyware_4945_1
{
strings:
	$a0 = { 5751590f02fe538b7c240483c4 }


condition:
	$a0
}