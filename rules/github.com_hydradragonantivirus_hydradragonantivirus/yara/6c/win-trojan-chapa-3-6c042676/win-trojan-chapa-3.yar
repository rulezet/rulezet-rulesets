rule Win_Trojan_Chapa_3
{
strings:
	$a0 = { b9b601f3a4b821250e061fba3102cd21b81335cd21891e0f028c061102b81325ba1402cd21 }


condition:
	$a0
}