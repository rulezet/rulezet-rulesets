rule Win_Trojan_Cascade_11
{
strings:
	$a0 = { d9eb04464943418db74d01bc82068134f066464c75f8 }


condition:
	$a0
}