rule Win_Trojan_Killfiles_60
{
strings:
	$a0 = { 64656c2f462f512f53202553797374656d526f6f74255c7461736b6d67722e6578653e6e756c }


condition:
	$a0
}