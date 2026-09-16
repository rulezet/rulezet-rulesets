rule Win_Trojan_Duddie_1
{
strings:
	$a0 = { 633a5c746d702e626d7000008b80f00200008b8090000000ba2ceb4500e836b3ffffc300ff }


condition:
	$a0
}