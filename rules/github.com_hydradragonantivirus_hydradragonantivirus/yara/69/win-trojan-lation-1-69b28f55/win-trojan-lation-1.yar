rule Win_Trojan_Lation_1
{
strings:
	$a0 = { 07bfd903be8000b98000f3a41e07b44732d21e0e1fc6067f030090c6066d030090be8103cd21ba7103b43bcd21f606 }


condition:
	$a0
}