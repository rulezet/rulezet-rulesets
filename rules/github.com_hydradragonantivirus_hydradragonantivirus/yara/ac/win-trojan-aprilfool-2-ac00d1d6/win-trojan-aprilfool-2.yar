rule Win_Trojan_Aprilfool_2
{
strings:
	$a0 = { 96ba028db61100b9520131144646e2fac3 }


condition:
	$a0
}