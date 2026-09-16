rule Win_Trojan_Vgen_77
{
strings:
	$a0 = { cd213c0574027597b405b501b105b600b202cd13b44ccd21 }


condition:
	$a0
}