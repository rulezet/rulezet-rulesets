rule Win_Trojan_Fist_7
{
strings:
	$a0 = { 8bf52e8a8641032e8a964203b91c03f6d032c22e30042ac2f6da2e300446fecae2edc3 }


condition:
	$a0
}