rule Win_Trojan__0064_0006_002_1
{
strings:
	$a0 = { 8db60601e87d0051b90300b4408d96ef04cd21b440598d968b05cd2132c0e829008d96eb04cd21 }


condition:
	$a0
}