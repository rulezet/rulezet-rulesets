rule Win_Trojan_Birgit_34
{
strings:
	$a0 = { 2ec686d802e92e899ed902b90300eb005133c9e85600b002e84700b4408d96d80259cd217210 }


condition:
	$a0
}