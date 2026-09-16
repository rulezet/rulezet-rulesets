rule Win_Trojan_VGEN_679
{
strings:
	$a0 = { ccf4b8b9c8ba2389f7e293b8f915ba576ef7e28acb80e11fd3e8968b85b00cba71e3f7e22bc605bcbe055b9d8785 }


condition:
	$a0
}