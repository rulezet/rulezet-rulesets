rule Win_Trojan_Small_4127
{
strings:
	$a0 = { c60fe81c0000008d6d0439ef75ecffe389eb81eb2226460389df8dbb7c070000535dc38b760431c050 }


condition:
	$a0
}