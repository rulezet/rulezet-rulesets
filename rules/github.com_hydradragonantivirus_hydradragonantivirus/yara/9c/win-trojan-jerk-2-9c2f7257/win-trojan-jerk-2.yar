rule Win_Trojan_Jerk_2
{
strings:
	$a0 = { 1aba3e0501ea89969402cd21b419cd218886f804bbffff }


condition:
	$a0
}