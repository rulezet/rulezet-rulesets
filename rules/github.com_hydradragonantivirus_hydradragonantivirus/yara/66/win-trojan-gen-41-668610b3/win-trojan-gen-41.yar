rule Win_Trojan_Gen_41
{
strings:
	$a0 = { 9685058db61c00b9b20231144646e2fac3e800005d81edbe05eb00c3 }


condition:
	$a0
}