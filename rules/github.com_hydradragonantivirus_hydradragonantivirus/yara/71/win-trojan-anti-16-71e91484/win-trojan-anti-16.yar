rule Win_Trojan_Anti_16
{
strings:
	$a0 = { cd21b80935cd21891e44018c0646 }


condition:
	$a0
}