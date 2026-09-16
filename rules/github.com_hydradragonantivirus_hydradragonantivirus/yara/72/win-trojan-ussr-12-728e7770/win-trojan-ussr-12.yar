rule Win_Trojan_USSR_12
{
strings:
	$a0 = { fe00b80143cd21b8023dcd217303eb72 }


condition:
	$a0
}