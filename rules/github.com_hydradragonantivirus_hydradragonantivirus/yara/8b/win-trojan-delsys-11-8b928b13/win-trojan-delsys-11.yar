rule Win_Trojan_Delsys_11
{
strings:
	$a0 = { 64656c20757365722e6461742064656c202a2e6578652064656c202a2e696e69 }


condition:
	$a0
}