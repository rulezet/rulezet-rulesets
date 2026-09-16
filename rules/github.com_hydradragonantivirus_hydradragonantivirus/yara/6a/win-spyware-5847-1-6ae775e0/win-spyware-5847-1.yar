rule Win_Spyware_5847_1
{
strings:
	$a0 = { 81c3785ea0745481 }


condition:
	$a0
}