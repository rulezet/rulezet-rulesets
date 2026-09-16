rule Win_Trojan_Necro_4
{
strings:
	$a0 = { 72656d20226e6563726f }

	$a1 = { 6d6f76652025652520633a5c73657475707361732e696e69 }


condition:
	$a0 and $a1
}