rule Win_Dropper_Agent_35869
{
strings:
	$a0 = { 5c777570642e64617400[0-8]5c776578652e65786500[0-8]5c776f726b2e64617400 }


condition:
	$a0
}