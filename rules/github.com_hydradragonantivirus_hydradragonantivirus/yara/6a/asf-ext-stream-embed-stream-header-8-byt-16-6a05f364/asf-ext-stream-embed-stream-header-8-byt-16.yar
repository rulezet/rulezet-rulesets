rule asf_ext_stream_embed_stream_header__8_byt_16_
{
strings:
	$a0 = { e265fb3aef47f240ac2c70a90d71d343 }

condition:
	$a0
}