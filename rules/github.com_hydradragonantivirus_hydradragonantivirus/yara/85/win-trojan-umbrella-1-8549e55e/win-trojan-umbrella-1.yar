rule Win_Trojan_Umbrella_1
{
strings:
	$a0 = { d60bb8004233c933d2cd21720ab440bad40bb92000cd21b801572e8b0e800b2e8b167e0bcd }


condition:
	$a0
}