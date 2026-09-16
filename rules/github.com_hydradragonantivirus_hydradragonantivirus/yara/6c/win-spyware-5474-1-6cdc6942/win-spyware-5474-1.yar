rule Win_Spyware_5474_1
{
strings:
	$a0 = { e803000000ce8731e805000000 }


condition:
	$a0
}