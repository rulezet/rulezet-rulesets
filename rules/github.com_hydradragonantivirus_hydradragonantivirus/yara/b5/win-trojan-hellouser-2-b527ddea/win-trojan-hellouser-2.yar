rule Win_Trojan_HelloUser_2
{
strings:
	$a0 = { e800005d81ed08018db62601e80200eb108b9671028bfeb94b01ac32c2aae2fac3 }


condition:
	$a0
}