rule Win_Trojan_Mini_34
{
strings:
	$a0 = { 57a5a4bdcf00ba00ff8bfab41acd21b44e8bd6cd21 }


condition:
	$a0
}