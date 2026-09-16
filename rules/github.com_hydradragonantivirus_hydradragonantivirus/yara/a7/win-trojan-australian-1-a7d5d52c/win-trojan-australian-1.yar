rule Win_Trojan_Australian_1
{
strings:
	$a0 = { 1327e8fffcf4ea13b7ebf6aed4d9d8fddce1af0b23dbf65dad54fee95fe5e824ccebf6da2741a950 }


condition:
	$a0
}