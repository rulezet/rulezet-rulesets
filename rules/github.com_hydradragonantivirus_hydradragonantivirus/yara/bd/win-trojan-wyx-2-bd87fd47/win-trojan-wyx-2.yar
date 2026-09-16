rule Win_Trojan_WYX_2
{
strings:
	$a0 = { 0e1fb413a0787cb725be747cb347b90b01b669280446b28be2f9 }


condition:
	$a0
}