rule Win_Trojan_Influenza_1
{
strings:
	$a0 = { c6064b02000e1fb440b9b402ba0000cd21b8004233c999cd210e1fb440b91c00ba2f02cd21b43e }


condition:
	$a0
}