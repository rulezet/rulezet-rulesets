rule Win_Trojan_Ninja_1
{
strings:
	$a0 = { bf042e8b16c104e80100c39c2eff1eb304c3065033c08ec033c9268a0e6c005807c3e8edff }


condition:
	$a0
}