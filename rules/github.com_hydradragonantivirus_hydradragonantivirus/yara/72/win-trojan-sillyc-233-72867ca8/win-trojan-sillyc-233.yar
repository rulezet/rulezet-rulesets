rule Win_Trojan_SillyC_233
{
strings:
	$a0 = { d7b96300b440cd21598edeb440cd21ebbfbe6301fa57 }


condition:
	$a0
}