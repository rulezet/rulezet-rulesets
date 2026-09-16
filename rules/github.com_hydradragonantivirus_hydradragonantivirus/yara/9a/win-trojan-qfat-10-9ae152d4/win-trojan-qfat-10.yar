rule Win_Trojan_QFat_10
{
strings:
	$a0 = { f6eb158d8600fe5056b8010050b8020050e81f3083c4084683fe047ce6b8940150e8312759ebf6 }


condition:
	$a0
}