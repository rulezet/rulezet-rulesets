rule Win_Trojan_Gbot_24
{
strings:
	$a0 = { 55fc8bec81c49cfbffff8d85c0fcffff6880010000506800100000e8??00000083e80303d10fafc2????????00b9fe00000023c1a8fe74??b8570000006a006a00f2ff15 }


condition:
	$a0
}