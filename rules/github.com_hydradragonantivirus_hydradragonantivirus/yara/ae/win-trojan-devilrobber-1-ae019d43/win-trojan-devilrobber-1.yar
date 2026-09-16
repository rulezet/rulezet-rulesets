rule Win_Trojan_DevilRobber_1
{
strings:
	$a0 = { 2e2f706f6c69706f202d6320706f6c69706f2e6366672026 }


condition:
	$a0
}