rule Win_Trojan_Birthday_1
{
strings:
	$a0 = { bbff0043813fcdab75f9817f02debc75f283eb0381eb00018bfb }


condition:
	$a0
}