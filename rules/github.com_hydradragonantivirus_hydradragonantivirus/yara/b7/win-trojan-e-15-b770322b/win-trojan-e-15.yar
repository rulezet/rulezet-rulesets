rule Win_Trojan_E_15
{
strings:
	$a0 = { 910050cbfa33c08ec00e1f26a14c00a3030226a14e00a3050226c7064c001a0126891e4e00fb07 }


condition:
	$a0
}