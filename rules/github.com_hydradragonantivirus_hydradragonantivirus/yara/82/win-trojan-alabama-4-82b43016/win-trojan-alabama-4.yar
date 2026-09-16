rule Win_Trojan_Alabama_4
{
strings:
	$a0 = { 06f900013cd375062ec606f90000bb40008edb33db8a4717240c3c0c7541 }


condition:
	$a0
}