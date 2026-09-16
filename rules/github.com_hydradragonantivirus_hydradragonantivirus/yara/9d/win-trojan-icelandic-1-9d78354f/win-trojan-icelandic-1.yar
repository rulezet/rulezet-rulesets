rule Win_Trojan_Icelandic_1
{
strings:
	$a0 = { 30be0000b82e3a3b04741546e2f9b900 }


condition:
	$a0
}