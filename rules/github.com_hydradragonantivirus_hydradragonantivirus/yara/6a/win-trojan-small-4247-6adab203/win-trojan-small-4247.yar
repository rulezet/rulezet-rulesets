rule Win_Trojan_Small_4247
{
strings:
	$a0 = { fce8070000009d8f4000913f6159ff21 }


condition:
	$a0
}