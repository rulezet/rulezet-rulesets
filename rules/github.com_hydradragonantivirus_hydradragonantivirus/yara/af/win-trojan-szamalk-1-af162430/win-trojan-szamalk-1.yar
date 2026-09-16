rule Win_Trojan_Szamalk_1
{
strings:
	$a0 = { cd2181f9c807726980fe09726480fa01755fe8ab01b00250b98000ba00001e8edabb0000cd26 }


condition:
	$a0
}