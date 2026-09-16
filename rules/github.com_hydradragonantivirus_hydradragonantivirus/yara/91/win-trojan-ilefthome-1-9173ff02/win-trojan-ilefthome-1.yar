rule Win_Trojan_Ilefthome_1
{
strings:
	$a0 = { e800005d83ed03e867008dbe0001e828032ec686a30309e8e6007203e827018d96ac03e80e03e8d7 }


condition:
	$a0
}