rule asf_stream_group_guid__8_byt_16_
{
strings:
	$a0 = { ce75f87b8d46d1118d82006097c9a2b2 }

condition:
	$a0
}