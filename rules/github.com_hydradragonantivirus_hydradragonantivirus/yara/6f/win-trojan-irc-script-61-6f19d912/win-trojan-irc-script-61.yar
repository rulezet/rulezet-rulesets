rule Win_Trojan_IRC_Script_61
{
strings:
	$a0 = { 6e383d25636c6f6e652e636f6e2e636f756e7420310d0a6e393d25636c6f6e652e746d702e6e69636b }


condition:
	$a0
}