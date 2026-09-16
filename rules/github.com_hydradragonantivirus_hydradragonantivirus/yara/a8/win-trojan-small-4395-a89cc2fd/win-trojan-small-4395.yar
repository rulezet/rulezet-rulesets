rule Win_Trojan_Small_4395
{
strings:
	$a0 = { 6800764000585068800b000050 }


condition:
	$a0
}