rule Win_Trojan_Secretar_1
{
strings:
	$a0 = { 417cb800008ed8bf13048b052d0300890540ba4000f7e28ec00e1fb802028a16417c8a3640 }


condition:
	$a0
}