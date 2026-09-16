rule Win_Trojan_VGEN_607
{
strings:
	$a0 = { fb1e06b83130bbaddecd213dadde7503e9890106b452cd21268b47fe2ea33805078ed84039060100751b813e03 }


condition:
	$a0
}