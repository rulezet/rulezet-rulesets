rule Win_Trojan_Fist_9
{
strings:
	$a0 = { 8bf52e8a8651032e8a965203b92c03f6d832d02e30042ac2f6d22e300446fecae2edc3 }


condition:
	$a0
}