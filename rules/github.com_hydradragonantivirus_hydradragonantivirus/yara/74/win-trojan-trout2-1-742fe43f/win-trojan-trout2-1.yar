rule Win_Trojan_Trout2_1
{
strings:
	$a0 = { ca81d1665883ef01b454cd2120d212f7461aff020633c084f9b454cd2120e212c746d0f822faf6d9f6d7b401cd1383 }


condition:
	$a0
}