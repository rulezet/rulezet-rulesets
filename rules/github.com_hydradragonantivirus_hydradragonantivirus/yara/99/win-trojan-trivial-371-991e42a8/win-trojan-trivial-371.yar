rule Win_Trojan_Trivial_371
{
strings:
	$a0 = { 02ba9e00b43dcd2193b95400ba0000b440cd21b43ecd21b90000ba4f18b000b707b406cd10 }


condition:
	$a0
}