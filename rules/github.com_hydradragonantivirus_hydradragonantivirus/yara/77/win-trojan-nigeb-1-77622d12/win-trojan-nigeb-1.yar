rule Win_Trojan_Nigeb_1
{
strings:
	$a0 = { e800005b83c30c8bf383eb12e85a03a7e3426947cb6f6f }


condition:
	$a0
}