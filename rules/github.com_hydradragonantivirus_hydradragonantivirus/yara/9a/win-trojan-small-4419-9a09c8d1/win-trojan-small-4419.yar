rule Win_Trojan_Small_4419
{
strings:
	$a0 = { e804000000??764000588b00505068ec }


condition:
	$a0
}