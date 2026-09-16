rule Win_Trojan_Delf_407
{
strings:
	$a0 = { 7361626c655461736b4d67720000558bec81c4b8feffff53565733d28995c0feffff8995b8feffff8995bcfeffff8995d0feffff8995c4feffff8995ccfeffff8995c8feffff8945fc8b45 }


condition:
	$a0
}