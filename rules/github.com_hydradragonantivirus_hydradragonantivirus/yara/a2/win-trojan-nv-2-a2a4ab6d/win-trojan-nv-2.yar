rule Win_Trojan_NV_2
{
strings:
	$a0 = { 8000b440cd21b43e85db7402cd21e91cff33c08ed8fac4069000e800005f83c733902e89052e8c }


condition:
	$a0
}