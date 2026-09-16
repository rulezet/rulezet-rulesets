rule Win_Trojan_POPP53A_1
{
strings:
	$a0 = { 3a292e890e7801b440b9140299cd217302722db80042b9000099cd21b440b90500ba7701cd2172 }


condition:
	$a0
}