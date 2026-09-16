rule Win_Trojan_Ksenia_4
{
strings:
	$a0 = { 57e87f002e890edf142e8916e114c3b801572e8b0edf142e8b16e114e86400c3b440e85e00c3 }


condition:
	$a0
}