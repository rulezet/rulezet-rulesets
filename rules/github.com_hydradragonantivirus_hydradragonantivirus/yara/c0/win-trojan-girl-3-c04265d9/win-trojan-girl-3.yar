rule Win_Trojan_Girl_3
{
strings:
	$a0 = { 3b551d053cfc0e07b917008db6e3038bfeacf6d0aae2fac3 }


condition:
	$a0
}