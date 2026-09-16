rule Win_Trojan_Bootache_2
{
strings:
	$a0 = { f36658825857fb6c5e0c62303e8cc061f023ef59256b6e226a6c5f1228ea7677c43ea7359847458c }


condition:
	$a0
}