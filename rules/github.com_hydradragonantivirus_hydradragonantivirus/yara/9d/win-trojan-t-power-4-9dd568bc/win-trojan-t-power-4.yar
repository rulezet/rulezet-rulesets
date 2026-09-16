rule Win_Trojan_T_Power_4
{
strings:
	$a0 = { 41ad2da3c005d9b4cf9447ade0a3c4e14f992ce0d9b4cfa0ede38cd944540ed8cfd9cf305f6be498 }


condition:
	$a0
}