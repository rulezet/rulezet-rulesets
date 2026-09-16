rule Win_Trojan_Crypt_145
{
strings:
	$a0 = { 81c2????????(01|29|31)(10|11|13|16|17)81ea[0-20]3b(c2|ca|da|ea|f2|fa)0f82??ffffff }


condition:
	$a0
}