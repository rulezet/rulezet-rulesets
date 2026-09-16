rule Win_Trojan_E_20
{
strings:
	$a0 = { c08ed8b8f50187064c0026a3fd015887064e0026a3ff01 }


condition:
	$a0
}