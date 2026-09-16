rule PSCHF___Pukall_Stream_Cipher_Hash_Function__8_byt_STR_16_
{
strings:
	$a0 = { 52656d7361616c707321313233343536 }

condition:
	$a0
}