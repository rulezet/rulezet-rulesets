rule Win_Trojan_T_Power_7
{
strings:
	$a0 = { 6a00078d869e01bf0400abbf0c00ab8cc8abb4ccebfd }


condition:
	$a0
}