rule asf_stream_header_guid__8_byt_16_
{
strings:
	$a0 = { 9107dcb7b7a9cf118ee600c00c205365 }

condition:
	$a0
}