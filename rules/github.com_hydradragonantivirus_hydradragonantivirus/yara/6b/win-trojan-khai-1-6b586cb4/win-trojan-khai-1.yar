rule Win_Trojan_Khai_1
{
strings:
	$a0 = { c38bf02d0300b913073004300c46e2f9e959fe }


condition:
	$a0
}