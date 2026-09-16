rule Win_Trojan_Intruder_6
{
strings:
	$a0 = { 67037518e86b03e86e03e826007509e89103e8e401 }


condition:
	$a0
}