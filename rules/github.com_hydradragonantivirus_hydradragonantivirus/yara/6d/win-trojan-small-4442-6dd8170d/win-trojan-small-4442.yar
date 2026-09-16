rule Win_Trojan_Small_4442
{
strings:
	$a0 = { 6a00c70424007640008d04240f6e100f }


condition:
	$a0
}