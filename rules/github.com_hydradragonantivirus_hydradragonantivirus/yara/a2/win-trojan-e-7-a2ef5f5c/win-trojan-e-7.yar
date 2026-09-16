rule Win_Trojan_E_7
{
strings:
	$a0 = { 1380fcfa74108cd8488ed82916120029160300e81e }


condition:
	$a0
}