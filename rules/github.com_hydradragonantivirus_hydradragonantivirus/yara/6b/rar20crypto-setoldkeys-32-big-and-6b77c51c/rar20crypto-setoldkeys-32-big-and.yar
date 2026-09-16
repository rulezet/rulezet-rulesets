rule Rar20Crypto_SetOldKeys__32_big_AND_
{
strings:
	$a0 = { d3a3b879[0-20]3f6d12f7[0-20]7515a235[0-20]a4e7f123 }

condition:
	$a0
}