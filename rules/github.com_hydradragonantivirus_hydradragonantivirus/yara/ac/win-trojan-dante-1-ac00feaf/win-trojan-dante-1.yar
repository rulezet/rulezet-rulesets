rule Win_Trojan_Dante_1
{
strings:
	$a0 = { 02b93201b4408d960301cd2133c933d2b80042cd21b4408d96a102b90300cd21b801575a }


condition:
	$a0
}