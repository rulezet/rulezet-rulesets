rule Win_Trojan_G2_11
{
strings:
	$a0 = { 1e06b84144cd213d535074438cd8488ed8832e }


condition:
	$a0
}