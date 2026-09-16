rule Win_Trojan_Small_4437
{
strings:
	$a0 = { 6a00c70424004440008d04240f6e100f }


condition:
	$a0
}