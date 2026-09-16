rule Win_Trojan_OpalSoft_1
{
strings:
	$a0 = { 13fbfba67816f8afaba9ade5fd4fcb36dac7fe89e667a04304f4d838ab6667a3defb0bc6fb0b8ff1 }


condition:
	$a0
}