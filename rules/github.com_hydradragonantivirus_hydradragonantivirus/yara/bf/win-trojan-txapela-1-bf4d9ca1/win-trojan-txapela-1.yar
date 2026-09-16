rule Win_Trojan_Txapela_1
{
strings:
	$a0 = { 09b805feebfc80c43bebf4bb1a000e07cd21b001cd21eb02ebfec606220082b080e6212ea039 }


condition:
	$a0
}