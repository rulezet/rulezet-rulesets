rule Win_Trojan_Killfiles_61
{
strings:
	$a0 = { 64656c2f462f512f53202553797374656d526f6f74255c6e746f736b726e6c2e6578653e6e756c }


condition:
	$a0
}