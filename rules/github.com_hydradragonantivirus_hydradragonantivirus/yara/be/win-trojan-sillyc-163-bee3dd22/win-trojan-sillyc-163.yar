rule Win_Trojan_SillyC_163
{
strings:
	$a0 = { 01b43fb5ffcd2150803e6c01b87414b8004233c933d2cd21595183c16dfec6b440cd2158b44f }


condition:
	$a0
}