rule Win_Trojan_Metal_2
{
strings:
	$a0 = { 9c019a0e00ea009a890097005589e5b800019acd029c0181ec0001c706902201008dbe00ff165731c0509acf08 }


condition:
	$a0
}