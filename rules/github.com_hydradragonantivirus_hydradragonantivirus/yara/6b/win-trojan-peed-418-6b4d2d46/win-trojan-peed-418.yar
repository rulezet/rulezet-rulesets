rule Win_Trojan_Peed_418
{
strings:
	$a0 = { 8d0438056e6200003d6e62000074263d6cf600007f1fff21 }


condition:
	$a0
}