rule Win_Trojan_Radiation_1
{
strings:
	$a0 = { 01b94d012e311483c602e2f8c3b42ccd212e8996de03e8dfffb4408d960001b9e102cd21e8 }


condition:
	$a0
}