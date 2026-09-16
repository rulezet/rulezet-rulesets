rule Win_Trojan_Afori_1
{
strings:
	$a0 = { 1e0500b57403e9e300b82435cd21520e1fbaa800b824 }


condition:
	$a0
}