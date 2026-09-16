rule Win_Trojan_Jack_1
{
strings:
	$a0 = { 9afc773a3de8037235c605fcc64501e92d04008945028d54f3ffd6b428b9b4018bd3cd210ac075 }


condition:
	$a0
}