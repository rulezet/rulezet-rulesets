rule Win_Trojan_Monxla_4
{
strings:
	$a0 = { b9feff23c18bc8b80143ba260003 }


condition:
	$a0
}