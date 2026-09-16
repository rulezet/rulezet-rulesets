rule Win_Trojan_Bolero_2
{
strings:
	$a0 = { 95bfcf0303fd2e813dc3c37416b9be03bf2a0003fdb2 }


condition:
	$a0
}