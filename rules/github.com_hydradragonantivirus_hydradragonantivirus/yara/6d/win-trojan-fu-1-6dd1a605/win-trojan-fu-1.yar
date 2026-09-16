rule Win_Trojan_Fu_1
{
strings:
	$a0 = { b4e1cd2180fce1731680fc047211b4 }


condition:
	$a0
}