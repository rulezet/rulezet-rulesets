rule Win_Trojan_Sirius_21
{
strings:
	$a0 = { e80000582d0901958db62301568b961302b978008bfead33c2abe2fac3 }


condition:
	$a0
}