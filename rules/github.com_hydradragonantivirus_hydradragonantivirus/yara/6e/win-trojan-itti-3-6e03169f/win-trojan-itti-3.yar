rule Win_Trojan_Itti_3
{
strings:
	$a0 = { cab80042cd21b440b96300ba0001cd21b43ecd219dc3 }


condition:
	$a0
}