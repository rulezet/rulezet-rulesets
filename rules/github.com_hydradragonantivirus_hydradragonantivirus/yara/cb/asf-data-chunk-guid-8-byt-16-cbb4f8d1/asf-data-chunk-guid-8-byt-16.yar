rule asf_data_chunk_guid__8_byt_16_
{
strings:
	$a0 = { 3626b2758e66cf11a6d900aa0062ce6c }

condition:
	$a0
}