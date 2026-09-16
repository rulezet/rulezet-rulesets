rule Win_Trojan_Siskin_1
{
strings:
	$a0 = { 5e1e0681ee0300b4fecd2180fc00746ebd3d008cd003c5fb8ed0a102002bc5a30200978cd848501f292e03000e }


condition:
	$a0
}