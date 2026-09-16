rule Win_Trojan_Birgit_26
{
strings:
	$a0 = { a42ec6869902e92e899e9a02b90300eb005133c9e85600b002e84700b4408d96990259cd217210 }


condition:
	$a0
}