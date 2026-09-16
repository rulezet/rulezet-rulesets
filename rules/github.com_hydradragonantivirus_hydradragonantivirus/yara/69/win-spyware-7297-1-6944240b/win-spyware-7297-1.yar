rule Win_Spyware_7297_1
{
strings:
	$a0 = { 464e33de5681dee364ff49331c245e48 }


condition:
	$a0
}