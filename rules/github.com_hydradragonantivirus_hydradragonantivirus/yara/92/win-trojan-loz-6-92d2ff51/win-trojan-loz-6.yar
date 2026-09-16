rule Win_Trojan_Loz_6
{
strings:
	$a0 = { ee06bf0001b90300f3a4b4fecd2180fc4c7472b44abb0010cd21b448bbffffcd2183eb3183fb40725cb448cd2150 }


condition:
	$a0
}