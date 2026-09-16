rule TEA_encryption_decryption__0xc6ef3720__0x61c88647___32_lil_AND_
{
strings:
	$a0 = { 2037efc6[0-20]4786c861 }

condition:
	$a0
}