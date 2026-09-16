rule Win_Trojan_GP_3
{
strings:
	$a0 = { cd2180fcf7731380fc03072e8e16 }


condition:
	$a0
}