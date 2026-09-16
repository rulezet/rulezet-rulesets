rule Win_Trojan_Nuke5_1
{
strings:
	$a0 = { cc8b6efa81ed0300061eb84144cd213d535074438cd8488ed8832e03004090832e12004090 }


condition:
	$a0
}