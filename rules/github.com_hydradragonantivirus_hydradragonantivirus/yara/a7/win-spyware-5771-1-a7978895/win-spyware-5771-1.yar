rule Win_Spyware_5771_1
{
strings:
	$a0 = { 5089342468223de4 }


condition:
	$a0
}