rule Win_Trojan_Mini2_2
{
strings:
	$a0 = { 81ed06018db6da01bfff004757a5a4b98000be80008dbeeb01f3a4b41eb923008d96dd01e8a500730d8db6eb01bf }


condition:
	$a0
}