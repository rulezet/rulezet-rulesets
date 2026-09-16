rule Win_Spyware_Goldun_99
{
strings:
	$a0 = { 12f173796d61ea6315fb1b1bd1b6a0618c6d636166656513206c650947 }


condition:
	$a0
}