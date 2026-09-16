rule Win_Trojan_Bancos_774
{
strings:
	$a0 = { 3226d59046ab9bed9ffbd1e62dc63985ef318482c445cff3581b06b9c5b8915b26c8d3eb06279115ddc385f6c860d4c285c5816d5b85ab287af74a336fd6a59b12dbcbb8 }


condition:
	$a0
}