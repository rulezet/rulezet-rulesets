rule Win_Trojan_Antimon_3
{
strings:
	$a0 = { 2bd033c9b80042cd21ba0001b9aa05b440cd215a59 }


condition:
	$a0
}