rule Win_Trojan_Fist_8
{
strings:
	$a0 = { 8bf52e8a8648032e8a964903b9220390f6d832d02e30142ac2f6da2e300446fecae2edc3 }


condition:
	$a0
}