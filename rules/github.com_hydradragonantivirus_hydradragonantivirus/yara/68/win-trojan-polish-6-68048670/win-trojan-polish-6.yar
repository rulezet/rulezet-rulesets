rule Win_Trojan_Polish_6
{
strings:
	$a0 = { bf0000b90001f3a45e8bc6bf0000b90001f3a45e8bc605 }


condition:
	$a0
}