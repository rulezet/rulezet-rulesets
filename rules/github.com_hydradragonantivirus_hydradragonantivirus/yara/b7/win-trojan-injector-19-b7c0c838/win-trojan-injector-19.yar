rule Win_Trojan_Injector_19
{
strings:
	$a0 = { 7159565a535a735a6c6f63 }


condition:
	$a0
}