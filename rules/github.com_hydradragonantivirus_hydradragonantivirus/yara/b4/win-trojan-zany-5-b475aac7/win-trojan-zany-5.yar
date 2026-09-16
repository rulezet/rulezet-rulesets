rule Win_Trojan_Zany_5
{
strings:
	$a0 = { 81ed07018db6ba01bf000157a5a58d96be01e88e00b44e8d969e01b90000cd21727ae80400b44fe2f5b8023d8d96dc }


condition:
	$a0
}