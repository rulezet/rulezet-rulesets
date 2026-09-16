rule Win_Trojan_Fu_2
{
strings:
	$a0 = { e1cd2180fce1731680fc047211b4ddbf }


condition:
	$a0
}