rule Win_Trojan_PS_25
{
strings:
	$a0 = { 01b440b94a01ccb8004233c999ccb903008d96ba02b440ccfe86b902b801575a59ccb43ecc }


condition:
	$a0
}