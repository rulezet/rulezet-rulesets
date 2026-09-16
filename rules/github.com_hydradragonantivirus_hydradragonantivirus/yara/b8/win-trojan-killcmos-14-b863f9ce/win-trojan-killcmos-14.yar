rule Win_Trojan_KillCMOS_14
{
strings:
	$a0 = { 31dbb31088d8e670e6edb0ffe6714381fb80007302ebedb44ccd21 }


condition:
	$a0
}