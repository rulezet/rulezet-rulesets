rule Win_Trojan_Sirius_31
{
strings:
	$a0 = { 582d0801958db62401568b96c903b952018bfead33c2d1caabe2f8c3 }


condition:
	$a0
}