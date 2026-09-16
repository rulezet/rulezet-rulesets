rule Win_Trojan_Phantasmagoria_1
{
strings:
	$a0 = { 2025bbffff8edb33d2cd21b41aba8000cd215d5f5e }


condition:
	$a0
}