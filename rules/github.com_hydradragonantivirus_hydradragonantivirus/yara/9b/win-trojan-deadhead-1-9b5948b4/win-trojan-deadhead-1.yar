rule Win_Trojan_DeadHead_1
{
strings:
	$a0 = { 8ec00e1ffabb0400b93f0126890f26894f0883c3028cca26891726895708fb0e07cd01cceb }


condition:
	$a0
}