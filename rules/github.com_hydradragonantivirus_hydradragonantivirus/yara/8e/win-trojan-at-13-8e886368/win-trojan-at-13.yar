rule Win_Trojan_AT_13
{
strings:
	$a0 = { cd218c066900891e6700ba20008ec233ff26803d06740ee830018edab425ba5c00cd210e }


condition:
	$a0
}