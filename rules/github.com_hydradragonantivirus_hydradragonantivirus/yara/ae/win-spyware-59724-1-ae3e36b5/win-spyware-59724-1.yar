rule Win_Spyware_59724_1
{
strings:
	$a0 = { 558bec81c4d4feffff60837d0c010f85ad }


condition:
	$a0
}