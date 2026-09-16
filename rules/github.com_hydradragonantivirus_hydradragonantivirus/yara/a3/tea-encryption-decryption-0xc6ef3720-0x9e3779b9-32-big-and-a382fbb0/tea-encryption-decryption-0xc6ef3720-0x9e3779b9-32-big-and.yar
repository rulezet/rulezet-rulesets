rule TEA_encryption_decryption__0xc6ef3720__0x9e3779b9___32_big_AND_
{
strings:
	$a0 = { c6ef3720[0-20]9e3779b9 }

condition:
	$a0
}