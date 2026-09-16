rule Win_Trojan_Vicky_5
{
strings:
	$a0 = { ba0001b440eb00b93001eb00cd2190b801578b16c501eb00 }


condition:
	$a0
}