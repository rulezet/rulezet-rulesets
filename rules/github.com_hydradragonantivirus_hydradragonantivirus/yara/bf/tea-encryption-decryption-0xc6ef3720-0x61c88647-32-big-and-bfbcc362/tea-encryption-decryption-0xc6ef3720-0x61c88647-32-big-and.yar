rule TEA_encryption_decryption__0xc6ef3720__0x61c88647___32_big_AND_
{
strings:
	$a0 = { c6ef3720[0-20]61c88647 }

condition:
	$a0
}