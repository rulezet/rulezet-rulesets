rule Win_Trojan_VGEN_630
{
strings:
	$a0 = { 9a0000ba019a0d0058015589e5b800029acd02ba0181ec0002e872fcbf7a031e57bff9110e5731c0509a7006ba018dbe }


condition:
	$a0
}