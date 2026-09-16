rule Win_Trojan_Swlabs_1
{
strings:
	$a0 = { 010300550002000200ffffe80d000000020000030000000803 }


condition:
	$a0
}