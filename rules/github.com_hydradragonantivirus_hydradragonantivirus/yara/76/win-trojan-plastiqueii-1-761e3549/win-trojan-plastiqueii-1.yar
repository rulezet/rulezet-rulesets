rule Win_Trojan_PlastiqueII_1
{
strings:
	$a0 = { ffb84342cd213d78567513b84442bf }


condition:
	$a0
}