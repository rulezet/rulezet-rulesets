rule Win_Trojan_Nature_1
{
strings:
	$a0 = { cb02ba0001cd2133c87513b8004233c933d2cd21b440b90300baa401cd215a59b80157cd21 }


condition:
	$a0
}