rule Win_Trojan_Delf_2225
{
strings:
	$a0 = { 8b45f4bae4db4600e8ee6df9ff752eb201a110204100e8d05bf9ffa3c01d47008d45e4baf8db4600e85a6af9ff6a008b45e4e8786ef9ff50e8ce8bf9ff }


condition:
	$a0
}