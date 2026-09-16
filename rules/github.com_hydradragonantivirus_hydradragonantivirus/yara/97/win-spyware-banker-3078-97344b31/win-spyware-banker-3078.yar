rule Win_Spyware_Banker_3078
{
strings:
	$a0 = { 3c39ccfca90b2d0214344e231e39ce58786feb769e487085c6d28c2a5a73d7ac988ef0b837f9b02ad97245732fdff3de79a0 }


condition:
	$a0
}