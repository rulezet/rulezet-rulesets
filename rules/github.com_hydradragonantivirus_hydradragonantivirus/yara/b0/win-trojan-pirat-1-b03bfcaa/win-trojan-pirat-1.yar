rule Win_Trojan_Pirat_1
{
strings:
	$a0 = { d2cd3089f281c2a801b90500b440cd3089f2b97701b440cd308b84ca01050501a30101b8 }


condition:
	$a0
}