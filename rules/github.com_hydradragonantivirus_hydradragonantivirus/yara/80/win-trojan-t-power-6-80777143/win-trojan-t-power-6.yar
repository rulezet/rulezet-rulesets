rule Win_Trojan_T_Power_6
{
strings:
	$a0 = { 08ff6a00078d867301bf0400abbf0c00ab8cc8abb4ccebfd }


condition:
	$a0
}