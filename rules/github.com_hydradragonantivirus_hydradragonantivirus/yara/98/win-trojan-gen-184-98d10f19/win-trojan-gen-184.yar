rule Win_Trojan_Gen_184
{
strings:
	$a0 = { 576a019af50b6300bf8b071e57c43e0b080657ff360200bf0f081e579ae00c }


condition:
	$a0
}