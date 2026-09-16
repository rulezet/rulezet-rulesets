rule Win_Trojan_Hi_7
{
strings:
	$a0 = { 8c060103ba7f00b82125cd210e1f8ccb3e2b9eeb }


condition:
	$a0
}