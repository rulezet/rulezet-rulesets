rule Win_Trojan_Trojan_242
{
strings:
	$a0 = { 03001e06b84456cd2181f956447456b44abbffffcd2183eb38b44acd217246832e020038b448bb3700cd217238 }


condition:
	$a0
}