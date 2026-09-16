rule Win_Trojan_Rexan_1
{
strings:
	$a0 = { 018a1c2e021e1601881c4681fe120475f0e98002 }


condition:
	$a0
}