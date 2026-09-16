rule Win_Trojan_OnFire_1
{
strings:
	$a0 = { f1f847325432de47f9a232ded176c9cffed173e1cdfe95ffe0417bff40ddfe5a5a41dfff40d9fe5a }


condition:
	$a0
}