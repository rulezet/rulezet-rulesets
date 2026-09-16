rule Win_Trojan_Delfiles_4
{
strings:
	$a0 = { 64656c20255553455250524f46494c45255c4d7920446f63756d656e74735c2a }


condition:
	$a0
}