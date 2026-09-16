rule Win_Trojan_T_Power_3
{
strings:
	$a0 = { 08ff6a00078d867401bf0400abbf0c00ab8cc8abb4ccebfd }


condition:
	$a0
}