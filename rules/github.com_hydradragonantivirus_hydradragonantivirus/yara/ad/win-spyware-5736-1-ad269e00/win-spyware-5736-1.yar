rule Win_Spyware_5736_1
{
strings:
	$a0 = { 525683c40456893424331424 }


condition:
	$a0
}