rule Win_Trojan_Transhell_1
{
strings:
	$a0 = { 48656c6c6f2c48656c6c21 }


condition:
	$a0
}