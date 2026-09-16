rule anti_debug__PeID_OEP_Signature_Spoofing__8_byt_20_
{
strings:
	$a0 = { eb033a4d3a1eeb02cd209ceb02cd20eb02cd2060 }

condition:
	$a0
}