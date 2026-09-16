rule Win_Trojan_Shake_3
{
strings:
	$a0 = { 5e50e800005eb80342cd213d34 }


condition:
	$a0
}