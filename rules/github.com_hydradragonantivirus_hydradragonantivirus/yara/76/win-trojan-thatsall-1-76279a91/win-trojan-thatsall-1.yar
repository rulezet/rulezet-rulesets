rule Win_Trojan_ThatsAll_1
{
strings:
	$a0 = { 6b03b440ba6a03b90300cd30720fe82d00720ab440ba0001b96a02cd305a59b80157cd30b43e }


condition:
	$a0
}