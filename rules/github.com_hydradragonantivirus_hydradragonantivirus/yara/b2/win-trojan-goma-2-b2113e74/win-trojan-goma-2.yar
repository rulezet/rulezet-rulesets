rule Win_Trojan_Goma_2
{
strings:
	$a0 = { fb775481ea7c033e3b968004744981c27c033e89967c048d967f04cd21b440b979038d9606 }


condition:
	$a0
}