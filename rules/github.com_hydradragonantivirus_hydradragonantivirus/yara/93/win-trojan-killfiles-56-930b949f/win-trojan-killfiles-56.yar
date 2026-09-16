rule Win_Trojan_Killfiles_56
{
strings:
	$a0 = { 64656c20633a5c77696e646f77735c696e665c2a2e696e662064656c20633a5c7769 }


condition:
	$a0
}