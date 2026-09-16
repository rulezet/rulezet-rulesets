rule Win_Trojan_Vulcan_7
{
strings:
	$a0 = { 89167902b86d02894514ff4504b440595150ba0001cd2133d233c9b80042cd2158595acd21 }


condition:
	$a0
}