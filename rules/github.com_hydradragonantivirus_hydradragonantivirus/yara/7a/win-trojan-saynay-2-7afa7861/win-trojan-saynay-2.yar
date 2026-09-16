rule Win_Trojan_SayNay_2
{
strings:
	$a0 = { 5361794e6179fae850013e8b6e0081ed0d01fb8db69802bf0001b90900f3 }


condition:
	$a0
}