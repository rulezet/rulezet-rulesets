rule Win_Trojan_Cybercide_4
{
strings:
	$a0 = { cd213d333d75058d567cffe2b82135cd21899e8e }


condition:
	$a0
}