rule Win_Trojan_Fried_1
{
strings:
	$a0 = { cd2150bb6401b90100ba0000cd25b91b00be03018bfee82500b409ba6401cd21588ad0b80106b90000b600cd13b9 }


condition:
	$a0
}