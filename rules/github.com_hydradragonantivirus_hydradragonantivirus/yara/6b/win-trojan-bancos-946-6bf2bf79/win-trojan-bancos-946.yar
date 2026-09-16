rule Win_Trojan_Bancos_946
{
strings:
	$a0 = { 3ca4afe2a96ef7874e97039a42a4e2a519652347b7893efad86afa130b9a17a889a866834eeae312402ff4fb2cd41c6c060fa72dc772ea4d8a0ff95d8e640820 }


condition:
	$a0
}