rule Win_Trojan_Silly_76
{
strings:
	$a0 = { 64656c202f7120633a5c6e746c6472 }


condition:
	$a0
}