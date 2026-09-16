rule Win_Adware_WhiteSmoke_1
{
strings:
	$a0 = { 4f4654574152455c5768697465536d6f6b6500 }

	$a1 = { 8bff558bec8b4d085333db56573bcb74078b7d0c3bfb771be8????????6a165e893053535353 }


condition:
	$a0 and $a1
}