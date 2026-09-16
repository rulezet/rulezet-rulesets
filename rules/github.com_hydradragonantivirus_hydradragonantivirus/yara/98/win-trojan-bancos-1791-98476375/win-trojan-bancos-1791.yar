rule Win_Trojan_Bancos_1791
{
strings:
	$a0 = { 27d4f1e77691ed2480de985fd787767b8c94f59180f13d4717d9d7b50a9afa16213311c2ad991bb65f3e0619ee02e7bcb3abbe9243b7bf7ef90cb231d767992ffcc59ec72e21 }


condition:
	$a0
}