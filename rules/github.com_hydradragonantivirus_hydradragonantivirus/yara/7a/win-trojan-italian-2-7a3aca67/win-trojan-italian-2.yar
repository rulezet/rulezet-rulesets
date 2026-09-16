rule Win_Trojan_Italian_2
{
strings:
	$a0 = { c6863102e92e899e3202b90300eb005133c9e85600b002e84700b4408d96310259cd217210 }


condition:
	$a0
}