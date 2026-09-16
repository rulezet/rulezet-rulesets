rule Win_Trojan_CivilWar_1
{
strings:
	$a0 = { 42e8e3ffb440b90100ba9f03e8e6ffb440b90200baa603e8dbffb440b90200baae03e8d0ffc3 }


condition:
	$a0
}