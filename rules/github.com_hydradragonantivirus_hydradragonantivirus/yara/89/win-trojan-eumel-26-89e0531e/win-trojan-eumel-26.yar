rule Win_Trojan_Eumel_26
{
strings:
	$a0 = { e800005d81ed0a018db62501568bfe8b969c02b97701fcac32c2aae2fac3 }


condition:
	$a0
}