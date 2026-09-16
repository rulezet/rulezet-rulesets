rule Win_Trojan_Vundo_345
{
strings:
	$a0 = { 427511508b4424048038e97409803889740458c3eb01584a87c087db86db609c }


condition:
	$a0
}