rule Win_Trojan_DeadHead_2
{
strings:
	$a0 = { bb1501a10201310743e2fbb800008ec00e1ffabb0400b93d0126890f26894f0883c3028cca26891726895708fb }


condition:
	$a0
}