rule Win_Trojan_Fakeav_45
{
strings:
	$a0 = { a6feeb388210f9c456655a8e13ccfbf83f66ad68941e2956c98a9b2f97cc923c8cd0ca913c93 }


condition:
	$a0
}