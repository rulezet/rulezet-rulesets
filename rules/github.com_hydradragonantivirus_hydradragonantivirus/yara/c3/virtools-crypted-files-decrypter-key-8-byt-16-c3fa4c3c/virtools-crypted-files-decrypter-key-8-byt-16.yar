rule Virtools__crypted_files_decrypter_key__8_byt_16_
{
strings:
	$a0 = { 9d0b085bd4137760e7103f0a2c55b80a }

condition:
	$a0
}