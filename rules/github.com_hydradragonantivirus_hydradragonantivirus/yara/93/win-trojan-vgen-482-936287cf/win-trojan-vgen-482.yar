rule Win_Trojan_VGEN_482
{
strings:
	$a0 = { 079c2eff1e1901500e1fb4492e8e062c00cd211e07ba800058b431cd21c3b90200b8070ecd }


condition:
	$a0
}