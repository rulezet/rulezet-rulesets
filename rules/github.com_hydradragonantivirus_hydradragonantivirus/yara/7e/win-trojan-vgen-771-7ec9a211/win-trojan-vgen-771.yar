rule Win_Trojan_VGEN_771
{
strings:
	$a0 = { 0c01b9910080340046e2fab44eba900133c9cd217271b8023dba9e00cd21938ed9418a266c040e1f88260801f6c401 }


condition:
	$a0
}