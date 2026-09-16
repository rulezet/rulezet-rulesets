rule Win_Spyware_6651_1
{
strings:
	$a0 = { 83e8f9e80406000070eb6701f9435e81 }


condition:
	$a0
}