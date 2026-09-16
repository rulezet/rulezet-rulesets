rule Win_Trojan_Kazydropper_1
{
strings:
	$a0 = { 2809000006[5]6f1d00000a7409000001[21]281e00000a6f1f00000a }


condition:
	$a0
}