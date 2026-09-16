rule Win_Trojan_Printerceptor_1
{
strings:
	$a0 = { b403b0025a59bbdb04cd13ebfefec1ebbdfec5b800b806538ec0b7008addd1c38ac12688075b }


condition:
	$a0
}