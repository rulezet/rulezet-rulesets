rule Win_Trojan_Smm_1
{
strings:
	$a0 = { 0833f6b9b807e83f008bd7b440cd21b8004233c999cd21582d0300a3dc00b440badb00b90400 }


condition:
	$a0
}