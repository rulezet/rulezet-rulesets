rule Win_Trojan_Sirius_30
{
strings:
	$a0 = { 582d0901958db62501568b969f02b9bd008bfead33c2d1caabe2f8c3 }


condition:
	$a0
}