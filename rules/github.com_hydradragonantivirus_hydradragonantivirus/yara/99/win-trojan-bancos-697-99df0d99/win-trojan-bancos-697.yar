rule Win_Trojan_Bancos_697
{
strings:
	$a0 = { 9394eb4cd7e2d8e61273dd4604e28abdf2a2ac6b87108a426eaf99879b40f93bea01d38b9145645a13ec9581bc9cf34d848f6d7522aebd4fe2cb51fe38f3e2e7 }


condition:
	$a0
}