rule Win_Trojan_KillCMOS_1
{
strings:
	$a0 = { 7132f6b02eee4232c0eecdb23f0d0a }


condition:
	$a0
}