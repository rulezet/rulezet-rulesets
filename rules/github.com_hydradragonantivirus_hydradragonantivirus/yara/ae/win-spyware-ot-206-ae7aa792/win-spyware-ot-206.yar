rule Win_Spyware_ot_206
{
strings:
	$a0 = { e8865f00006a1a9959f7f98b45fc5780c261ff45fc889030004100e8b961000083e804593945fc72d7 }


condition:
	$a0
}