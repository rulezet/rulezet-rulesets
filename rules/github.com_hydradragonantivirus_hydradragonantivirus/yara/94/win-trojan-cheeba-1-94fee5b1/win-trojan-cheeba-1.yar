rule Win_Trojan_Cheeba_1
{
strings:
	$a0 = { bf00010e8cc85705e000bf????5057cb }

	$a1 = { bf0001902e8035??4781ff????72f5 }


condition:
	$a0 and $a1
}