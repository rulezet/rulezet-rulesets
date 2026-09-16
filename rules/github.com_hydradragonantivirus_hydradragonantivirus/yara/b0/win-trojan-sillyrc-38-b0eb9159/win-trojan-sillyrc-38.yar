rule Win_Trojan_SillyRC_38
{
strings:
	$a0 = { 56453d77427501cf3d004b756c505351521eb8823dcd21 }


condition:
	$a0
}