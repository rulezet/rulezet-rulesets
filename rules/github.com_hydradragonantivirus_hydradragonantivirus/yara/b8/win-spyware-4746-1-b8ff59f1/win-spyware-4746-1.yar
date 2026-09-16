rule Win_Spyware_4746_1
{
strings:
	$a0 = { 565e505083c40450522b }


condition:
	$a0
}