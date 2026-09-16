rule Win_Trojan_Wizard_1
{
strings:
	$a0 = { 5a005589e5b800019a7c025a0081ec00019a0a095a00b001509a1900430083faff75053dffff7408bfcc020e57 }


condition:
	$a0
}