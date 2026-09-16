rule Win_Trojan_Murphy_15
{
strings:
	$a0 = { fc4d5a751d1f2e8b84f7fc2e8b9cf5fc }


condition:
	$a0
}