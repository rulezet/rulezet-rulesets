rule Win_Trojan_Example_1
{
strings:
	$a0 = { 09011e060e1f3e8b86d0023e8986ce023effb6d0023effb6d2023effb6d6023effb6d402b41a8d960003cd21b4 }


condition:
	$a0
}