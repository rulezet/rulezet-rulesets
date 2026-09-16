rule Win_Trojan_Sirius_28
{
strings:
	$a0 = { e80000582d0901958db62501568b968902b9b2008bfead33c2d1caabe2f8c3 }


condition:
	$a0
}